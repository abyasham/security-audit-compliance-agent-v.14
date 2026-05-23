"""
LiteLLM Gateway — unified interface to 6+ LLM providers for SACA v14.

Providers: ollama, deepseek, openai, openrouter, openrouter2, kimi (moonshot), nvidia_nim
Uses the litellm library which provides OpenAI-compatible interface.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

import litellm

logger = logging.getLogger(__name__)

# ─── Provider model strings for LiteLLM ─────────────────────────────────────

PROVIDER_MODELS: dict[str, str] = {
    "ollama": os.getenv("OLLAMA_MODEL", "ollama/deepseek-r1:8b"),
    "deepseek": os.getenv("DEEPSEEK_MODEL", "deepseek/deepseek-chat"),
    "openai": os.getenv("OPENAI_MODEL", "openai/gpt-4.1-mini-2025-04-14"),
    "openrouter": os.getenv("OPENROUTER1_MODEL", os.getenv("OPENROUTER_MODEL", "openrouter/google/gemma-4-31b-it")),
    "openrouter2": os.getenv("OPENROUTER2_MODEL", "openrouter/openrouter/owl-alpha"),
    "kimi": os.getenv("KIMI_MODEL", "moonshot/kimi-k2.5"),
    "nvidia": os.getenv("NVIDIA_MODEL", "nvidia_nim/mistralai/mistral-large-3-675b-instruct-2512"),
}

# Default provider (first available)
DEFAULT_PROVIDER = os.getenv("LLM_DEFAULT_PROVIDER", "ollama")


class LiteLLMGateway:
    """Unified chat completion gateway via litellm."""

    def __init__(self):
        # Configure API keys from environment
        self._configure()

    def _configure(self):
        """Set API keys on litellm."""
        for key, env_var in [
            ("openai", "OPENAI_API_KEY"),
            ("deepseek", "DEEPSEEK_API_KEY"),
            ("moonshot", "KIMI_API_KEY"),       # Kimi uses Moonshot protocol
            ("nvidia_nim", "NVIDIA_API_KEY"),
        ]:
            val = os.getenv(env_var, "")
            if val:
                setattr(litellm, f"{key}_key", val)

        # Dual OpenRouter keys — litellm supports multiple via openrouter_key
        or1 = os.getenv("OPENROUTER1_API_KEY", os.getenv("OPENROUTER_API_KEY", ""))
        or2 = os.getenv("OPENROUTER2_API_KEY", "")
        if or1:
            litellm.openrouter_key = or1
        if or2:
            # Store OR#2 for fallback retry; litellm natively uses openrouter_key
            self._openrouter2_key = or2

        # Ollama URL
        ollama_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434")
        if ollama_url:
            litellm.ollama_api_base = ollama_url

    # ─── Public API ─────────────────────────────────────────────────────

    def chat(
        self,
        messages: list[dict],
        config: dict | None = None,
        stream: bool = False,
        on_token: Callable[[str], None] | None = None,
        tools: list[dict] | None = None,
    ) -> str | dict:
        """
        Send a chat completion request.

        Args:
            messages: List of {"role": "...", "content": "..."} dicts
            config: Optional {"provider": "openai"} to override default
            stream: If True, use streaming. on_token callback receives each delta.
            on_token: Callback for each token in streaming mode.

        Returns:
            The assistant's text content, or a dict with content + tool_calls.
        """
        provider = (config or {}).get("provider", DEFAULT_PROVIDER)
        model = PROVIDER_MODELS.get(provider, PROVIDER_MODELS[DEFAULT_PROVIDER])
        model = self._normalize_model(provider, model)

        try:
            if stream:
                return self._stream_chat(model, messages, on_token)
            else:
                return self._sync_chat(model, messages, tools=tools)
        except Exception as exc:
            logger.error("LiteLLM chat failed (provider=%s, model=%s): %s", provider, model, exc)
            # Fallback: try ollama
            if provider != "ollama":
                try:
                    fallback_model = PROVIDER_MODELS["ollama"]
                    logger.info("Falling back to %s", fallback_model)
                    return self._sync_chat(fallback_model, messages)
                except Exception as fb_exc:
                    logger.error("Fallback also failed: %s", fb_exc)
            raise

    def _normalize_model(self, provider: str, model: str) -> str:
        """Ensure provider-prefixed model strings for LiteLLM."""
        if not model:
            return model

        prefixes = {
            "openrouter": "openrouter/",
            "openrouter2": "openrouter/",
            "openai": "openai/",
            "deepseek": "deepseek/",
            "kimi": "moonshot/",
            "nvidia": "nvidia_nim/",
            "ollama": "ollama/",
        }

        prefix = prefixes.get(provider)
        if prefix and not model.startswith(prefix) and not any(model.startswith(p) for p in prefixes.values()):
            return f"{prefix}{model}"

        return model

    def _sync_chat(self, model: str, messages: list[dict], tools: list[dict] | None = None) -> dict:
        kwargs: dict = {"model": model, "messages": messages, "timeout": 120}
        if tools:
            kwargs["tools"] = tools
        response = litellm.completion(**kwargs)
        content = response.choices[0].message.content or ""

        # Extract tool calls if present
        tool_calls = []
        tc = getattr(response.choices[0].message, "tool_calls", None)
        if tc:
            tool_calls = [
                {
                    "id": t.id,
                    "name": t.function.name,
                    "arguments": t.function.arguments,
                }
                for t in tc
            ]

        return {"content": content, "tool_calls": tool_calls}

    def _stream_chat(
        self,
        model: str,
        messages: list[dict],
        on_token: Callable[[str], None] | None,
    ) -> str:
        full_text = ""
        response = litellm.completion(
            model=model,
            messages=messages,
            stream=True,
            timeout=120,
        )
        for chunk in response:
            delta = chunk.choices[0].delta.content or ""
            if delta:
                full_text += delta
                if on_token:
                    on_token(delta)
        return full_text
