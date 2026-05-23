"""SACA v14 Python Core — FastAPI application for agent execution & LLM gateway."""

from __future__ import annotations

import json
import logging
import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator
from concurrent.futures import ProcessPoolExecutor

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

# Global process pool for pyshark-based network analysis (avoids asyncio event loop conflicts)
_process_pool: ProcessPoolExecutor | None = None

def _get_process_pool() -> ProcessPoolExecutor:
    global _process_pool
    if _process_pool is None:
        _process_pool = ProcessPoolExecutor(max_workers=2)
    return _process_pool

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("saca.core")

# ─── Lazy agent imports ─────────────────────────────────────────────────────

_network_agent = None
_policy_agent = None
_compliance_judge = None
_ragas_runner = None
_llm_gateway = None


def _get_llm():
    global _llm_gateway
    if _llm_gateway is None:
        from services.llm_gateway import LiteLLMGateway
        _llm_gateway = LiteLLMGateway()
    return _llm_gateway


def _get_network_agent():
    global _network_agent
    if _network_agent is None:
        from agents.network_agent import NetworkAgent
        _network_agent = NetworkAgent(llm_gateway=_get_llm())
    return _network_agent


def _get_policy_agent():
    global _policy_agent
    if _policy_agent is None:
        from agents.policy_agent import PolicyAgent
        _policy_agent = PolicyAgent(llm_gateway=_get_llm())
    return _policy_agent


def _get_compliance_judge():
    global _compliance_judge
    if _compliance_judge is None:
        from agents.compliance_judge import ComplianceJudge
        _compliance_judge = ComplianceJudge(llm_gateway=_get_llm())
    return _compliance_judge


def _get_ragas_runner():
    global _ragas_runner
    if _ragas_runner is None:
        from eval.ragas_runner import RagasRunner
        _ragas_runner = RagasRunner(llm_gateway=_get_llm())
    return _ragas_runner


def _build_app() -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        logger.info("SACA Python Core starting...")
        try:
            import spacy
            spacy.load("en_core_web_sm")
            logger.info("spaCy model loaded")
        except Exception:
            logger.warning("spaCy model not available — policy NER disabled")
        yield

    app = FastAPI(
        title="SACA v14 Python Core",
        version="0.2.0",
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Health ──────────────────────────────────────────────────────────

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "0.2.0"}

    @app.post("/test/echo")
    async def test_echo(body: dict):
        """Simple echo endpoint for debugging."""
        logger.info("[/test/echo] Received: %s", body)
        return {"echo": body, "status": "ok"}

    # ── NetworkAgent ────────────────────────────────────────────────────

    @app.post("/analyze/network")
    async def analyze_network(body: dict):
        """Run NetworkAgent on a pcap file via tshark subprocess."""
        import subprocess
        import json as json_mod
        try:
            file_path = body.get("filePath", "")
            if not file_path:
                raise HTTPException(400, "filePath is required")
            logger.info("NetworkAgent: analyzing %s via tshark", file_path)
            
            # Run tshark-based analyzer in a subprocess (avoids pyshark asyncio issues)
            runner_path = os.path.join(os.path.dirname(__file__), "network_analyzer_tshark.py")
            result = subprocess.run(
                ["python", runner_path, file_path],
                capture_output=True,
                text=True,
                timeout=120,  # 2 minute timeout
            )
            
            if result.returncode != 0:
                logger.error("NetworkAgent subprocess error: %s", result.stderr)
                raise HTTPException(500, f"NetworkAgent failed: {result.stderr}")
            
            output = json_mod.loads(result.stdout)
            if "error" in output:
                raise HTTPException(500, f"NetworkAgent failed: {output['error']}")
            
            logger.info("NetworkAgent: complete — %d conversations, %d anomalies", 
                       len(output.get("conversations", [])), len(output.get("anomalies", [])))
            return output
        except HTTPException:
            raise
        except subprocess.TimeoutExpired:
            logger.error("NetworkAgent timed out after 2 minutes")
            raise HTTPException(504, "NetworkAgent timed out after 2 minutes")
        except Exception as e:
            logger.error("NetworkAgent error: %s", str(e), exc_info=True)
            raise HTTPException(500, f"NetworkAgent failed: {str(e)}")

    # ── PolicyAgent ─────────────────────────────────────────────────────

    @app.post("/analyze/policy")
    async def analyze_policy(body: dict):
        """Run PolicyAgent on policy text."""
        try:
            from schema.models import ParsedPolicy
            import asyncio

            policy_text = body.get("policyText", "")
            source_format = body.get("sourceFormat", "text")
            logger.info("[/analyze/policy] Starting with len=%d", len(policy_text))

            parsed = ParsedPolicy(
                policyName=body.get("policyName", "Untitled"),
                sourceFormat=source_format,
                rawText=policy_text,
                rules=body.get("existingRules", []),
            )
            logger.info("[/analyze/policy] ParsedPolicy created: %s", parsed.policy_name)
            
            agent = _get_policy_agent()
            logger.info("[/analyze/policy] PolicyAgent obtained")
            
            result = agent.analyze(parsed, llm_config=body.get("llmConfig"))
            logger.info("[/analyze/policy] Analysis complete, returning result")
            return result
        except HTTPException:
            raise
        except Exception as e:
            logger.error("[/analyze/policy] ERROR: %s", str(e), exc_info=True)
            raise HTTPException(500, f"PolicyAgent failed: {str(e)}")

    # ── ComplianceJudge ─────────────────────────────────────────────────

    @app.post("/analyze/compliance")
    async def judge_compliance(body: dict):
        """Run ComplianceJudge with policy rules + network output."""
        import asyncio
        rules = body.get("rules", [])
        network_output = body.get("networkOutput", {})
        capture_file_path = body.get("captureFilePath", "")
        logger.info("ComplianceJudge: evaluating %d rules", len(rules))
        judge = _get_compliance_judge()
        result = judge.evaluate(
            policy_rules=rules,
            network_output=network_output,
            llm_config=body.get("llmConfig"),
            capture_file_path=capture_file_path,
        )
        return result

    # ── Chat Stream ─────────────────────────────────────────────────────

    @app.post("/chat/stream")
    async def chat_stream(body: dict):
        """SSE-chunked chat completion via LiteLLM."""
        messages = body.get("messages", [])
        provider = body.get("provider")

        async def event_stream() -> AsyncGenerator[str, None]:
            llm = _get_llm()
            try:
                tokens = []
                llm.chat(
                    messages,
                    config={"provider": provider} if provider else None,
                    stream=True,
                    on_token=lambda token: tokens.append(token),
                )
                for token in tokens:
                    yield f"data: {json.dumps({'delta': token})}\n\n"
                yield "data: [DONE]\n\n"
            except Exception as exc:
                logger.error("Chat stream error: %s", exc)
                yield f"data: {json.dumps({'error': str(exc)})}\n\n"
                yield "data: [DONE]\n\n"

        return StreamingResponse(
            event_stream(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )

    # ── RAGAS ───────────────────────────────────────────────────────────

    @app.post("/eval/ragas")
    async def run_ragas(body: dict):
        """Run RAGAS evaluation on session findings."""
        findings = body.get("findings", [])
        policy_text = body.get("policyText", "")
        session_id = body.get("sessionId", "")
        capture_file_path = body.get("captureFilePath", "")
        logger.info("RAGAS: evaluating %d findings for session %s", len(findings), session_id)
        runner = _get_ragas_runner()
        result = runner.evaluate_sync(
            findings=findings,
            policy_text=policy_text,
            session_id=session_id,
            capture_file_path=capture_file_path,
        )
        return result

    return app


app = _build_app()


if __name__ == "__main__":
    import uvicorn

    host = os.getenv("PYTHON_CORE_HOST", "0.0.0.0")
    port = int(os.getenv("PYTHON_CORE_PORT", "8000"))
    uvicorn.run("main:app", host=host, port=port)
