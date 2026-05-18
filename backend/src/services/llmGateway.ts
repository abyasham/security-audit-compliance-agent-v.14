import { config } from '../config';
import { LLMProviderConfig, LLMProviderType, LLMConfig, ChatMessage, ToolCall } from '../types';

/**
 * Build a provider from the global config by type.
 */
function buildProvider(type: LLMProviderType): LLMProviderConfig | null {
  switch (type) {
    case 'ollama':
      return { type: 'ollama', baseUrl: config.llmConfig.ollama.baseUrl, model: config.llmConfig.ollama.model, isActive: true };
    case 'deepseek':
      if (!config.llmConfig.deepseek.apiKey) return null;
      return { type: 'deepseek', apiKey: config.llmConfig.deepseek.apiKey, model: config.llmConfig.deepseek.model, isActive: true };
    case 'openrouter':
      if (!config.llmConfig.openrouter.apiKey) return null;
      return { type: 'openrouter', apiKey: config.llmConfig.openrouter.apiKey, model: config.llmConfig.openrouter.model, isActive: true };
    case 'openai':
      if (!config.llmConfig.openai.apiKey) return null;
      return { type: 'openai', apiKey: config.llmConfig.openai.apiKey, model: config.llmConfig.openai.model, isActive: true };
  }
}

/**
 * LLM Gateway — connects to Ollama (local), DeepSeek API, or OpenRouter API.
 * All three use OpenAI-compatible chat completion format.
 * 
 * Each provider has a timeout: Ollama gets 5s (quick fail if not running),
 * API providers get 60s (normal API response time).
 */
export class LLMGateway {
  private providers: LLMProviderConfig[];

  constructor() {
    this.providers = this.buildProviderChain();
  }

  /**
   * Set the selected provider from the user's session config.
   * Called before chat to respect user's provider choice.
   */
  setSelectedProvider(sessionLlmConfig?: LLMConfig): void {
    if (!sessionLlmConfig?.primary?.type) return;
    const selected = buildProvider(sessionLlmConfig.primary.type);
    if (selected) {
      // Set selected as first in chain
      this.providers = [selected, ...this.providers.filter(p => p.type !== selected.type)];
    }
  }

  private buildProviderChain(): LLMProviderConfig[] {
    const chain: LLMProviderConfig[] = [];

    const ollama = buildProvider('ollama');
    if (ollama) chain.push(ollama);

    const deepseek = buildProvider('deepseek');
    if (deepseek) chain.push(deepseek);

    const openai = buildProvider('openai');
    if (openai) chain.push(openai);

    const openrouter = buildProvider('openrouter');
    if (openrouter) chain.push(openrouter);

    return chain;
  }

  private getEndpoint(provider: LLMProviderConfig): string {
    switch (provider.type) {
      case 'ollama': return `${provider.baseUrl}/v1/chat/completions`;
      case 'deepseek': return 'https://api.deepseek.com/v1/chat/completions';
      case 'openrouter': return 'https://openrouter.ai/api/v1/chat/completions';
      case 'openai': return 'https://api.openai.com/v1/chat/completions';
    }
  }

  private getHeaders(provider: LLMProviderConfig): Record<string, string> {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (provider.type === 'deepseek' || provider.type === 'openrouter' || provider.type === 'openai') {
      headers['Authorization'] = `Bearer ${provider.apiKey}`;
    }
    if (provider.type === 'openrouter') {
      headers['HTTP-Referer'] = 'http://localhost:3001';
      headers['X-Title'] = 'SACA';
    }
    return headers;
  }

  private getTimeout(provider: LLMProviderConfig): number {
    // Ollama local: 5s timeout (quick fail if not running)
    // Cloud APIs: 60s timeout
    return provider.type === 'ollama' ? 5000 : 60000;
  }

  /**
   * Create a gateway that uses ONLY the specified provider.
   * Used for per-agent provider selection.
   */
  static forProvider(type: LLMProviderType): LLMGateway | null {
    const provider = buildProvider(type);
    if (!provider) return null;
    const gateway = new LLMGateway();
    gateway.providers = [provider];
    return gateway;
  }

  private buildRequestBody(
    provider: LLMProviderConfig,
    messages: ChatMessage[],
    tools?: any[],
    stream: boolean = false
  ): any {
    const body: any = {
      model: provider.model,
      messages: messages.map(m => {
        const msg: any = { role: m.role, content: m.content };
        // Include tool_call_id for 'tool' role messages (OpenAI-compatible)
        if (m.role === 'tool' && m.tool_call_id) {
          msg.tool_call_id = m.tool_call_id;
        }
        // Include tool_calls for 'assistant' messages that made tool calls
        if (m.role === 'assistant' && m.toolCalls && m.toolCalls.length > 0) {
          msg.tool_calls = m.toolCalls.map(tc => ({
            id: tc.id,
            type: 'function',
            function: {
              name: tc.name,
              arguments: JSON.stringify(tc.arguments),
            },
          }));
        }
        return msg;
      }),
      stream,
      max_tokens: 4096,
      temperature: 0.1,
    };

    if (tools && tools.length > 0) {
      body.tools = tools;
      body.tool_choice = 'auto';
    }

    return body;
  }

  /**
   * Fetch with timeout via AbortController.
   */
  private async fetchWithTimeout(url: string, options: RequestInit, timeoutMs: number): Promise<Response> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const response = await fetch(url, { ...options, signal: controller.signal });
      return response;
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Check if a provider is accessible (quick ping).
   */
  private async pingProvider(provider: LLMProviderConfig): Promise<boolean> {
    try {
      if (provider.type === 'ollama') {
        const res = await this.fetchWithTimeout(
          `${provider.baseUrl}/api/tags`,
          { method: 'GET' },
          3000
        );
        return res.ok;
      }
      // API providers: validate by checking the API key works
      return true; // Assume API providers work — error will be caught later
    } catch {
      return false;
    }
  }

  /**
   * Streaming chat with provider fallback.
   */
  async *chat(
    messages: ChatMessage[],
    tools?: any[]
  ): AsyncGenerator<
    { type: 'chunk'; content: string } | { type: 'tool_call'; toolCall: ToolCall } | { type: 'done' }
  > {
    const errors: string[] = [];

    for (const provider of this.providers) {
      // Skip Ollama quickly if not running
      if (provider.type === 'ollama' && !(await this.pingProvider(provider))) {
        errors.push('ollama: not running');
        continue;
      }

      try {
        const endpoint = this.getEndpoint(provider);
        const headers = this.getHeaders(provider);
        const body = this.buildRequestBody(provider, messages, tools, true);
        const timeout = this.getTimeout(provider);

        console.log(`[LLM] Streaming via ${provider.type} (${provider.model})...`);

        const response = await this.fetchWithTimeout(endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(body),
        }, timeout);

        if (!response.ok) {
          const errText = await response.text().catch(() => '');
          throw new Error(`${provider.type} returned ${response.status}: ${errText.slice(0, 200)}`);
        }

        if (!response.body) throw new Error('No response body');

        const reader = response.body.getReader();
        const decoder = new TextDecoder();
        let buffer = '';

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split('\n');
          buffer = lines.pop() || '';

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || !trimmed.startsWith('data: ')) continue;
            const data = trimmed.slice(6);
            if (data === '[DONE]') { yield { type: 'done' as const }; return; }

            try {
              const parsed = JSON.parse(data);
              if (parsed.choices?.[0]?.delta?.tool_calls) {
                for (const tc of parsed.choices[0].delta.tool_calls) {
                  yield { type: 'tool_call' as const, toolCall: { id: tc.id || '', name: tc.function?.name || '', arguments: this.parseToolArgs(tc.function?.arguments || '{}') } };
                }
              }
              const content = parsed.choices?.[0]?.delta?.content || '';
              if (content) yield { type: 'chunk' as const, content };
              if (parsed.choices?.[0]?.finish_reason === 'stop') { yield { type: 'done' as const }; return; }
            } catch { /* skip malformed JSON */ }
          }
        }
        yield { type: 'done' as const };
        return;
      } catch (err: any) {
        console.log(`[LLM] ${provider.type} failed: ${err.message}`);
        errors.push(`${provider.type}: ${err.message}`);
        continue;
      }
    }
    throw new Error(`All LLM providers failed:\n${errors.join('\n')}`);
  }

  /**
   * Non-streaming chat completion with provider fallback.
   */
  async chatComplete(messages: ChatMessage[], tools?: any[]): Promise<{ content: string; toolCalls?: ToolCall[] }> {
    const errors: string[] = [];

    for (const provider of this.providers) {
      if (provider.type === 'ollama' && !(await this.pingProvider(provider))) {
        errors.push('ollama: not running');
        continue;
      }

      try {
        const endpoint = this.getEndpoint(provider);
        const headers = this.getHeaders(provider);
        const body = this.buildRequestBody(provider, messages, tools, false);
        const timeout = this.getTimeout(provider);

        console.log(`[LLM] Chat via ${provider.type} (${provider.model})...`);

        const response = await this.fetchWithTimeout(endpoint, {
          method: 'POST',
          headers,
          body: JSON.stringify(body),
        }, timeout);

        if (!response.ok) {
          const errText = await response.text().catch(() => '');
          throw new Error(`${provider.type} returned ${response.status}: ${errText.slice(0, 200)}`);
        }

        const result: any = await response.json();
        const choice = result.choices?.[0]?.message;
        const content = choice?.content || '';
        const toolCalls: ToolCall[] = (choice?.tool_calls || []).map((tc: any) => ({
          id: tc.id,
          name: tc.function?.name || '',
          arguments: this.parseToolArgs(tc.function?.arguments || '{}'),
        }));

        console.log(`[LLM] ${provider.type} responded (${content.length} chars, ${toolCalls.length} tool calls)`);
        return { content, toolCalls: toolCalls.length > 0 ? toolCalls : undefined };
      } catch (err: any) {
        console.log(`[LLM] ${provider.type} failed: ${err.message}`);
        errors.push(`${provider.type}: ${err.message}`);
        continue;
      }
    }
    throw new Error(`All LLM providers failed:\n${errors.join('\n')}`);
  }

  isAvailable(): boolean {
    return this.providers.length > 0;
  }

  getStatus(): { providers: Array<{ type: LLMProviderType; model: string; configured: boolean }> } {
    return {
      providers: this.providers.map(p => ({
        type: p.type,
        model: p.model,
        configured: p.type === 'ollama' || !!p.apiKey,
      })),
    };
  }

  countTokens(text: string): number {
    return Math.ceil(text.length / 4);
  }

  private parseToolArgs(args: string): Record<string, any> {
    try { return JSON.parse(args); } catch { return {}; }
  }
}
