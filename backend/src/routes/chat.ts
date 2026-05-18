import { Router, Request, Response } from 'express';
import { SessionStore } from '../storage/sessionStore';
import { LLMGateway } from '../services/llmGateway';
import { ContextAssembler } from '../services/contextAssembler';
import { ToolExecutor } from '../services/toolExecutor';
import { ChatMessage } from '../types';
import { tsharkRunner } from '../services/sharedTshark';

export const chatRouter = Router();
const store = SessionStore.getInstance();
const llm = new LLMGateway();
const assembler = new ContextAssembler();
const executor = new ToolExecutor(tsharkRunner);

// ─── Send Chat Message (SSE Stream with Tool Loop) ─────────────────────────

chatRouter.post('/stream', async (req: Request, res: Response) => {
  try {
    const { sessionId, message } = req.body;

    if (!sessionId || !message) {
      return res.status(400).json({ success: false, error: 'sessionId and message are required' });
    }

    const session = store.getSession(sessionId);
    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found' });
    }

    if (!llm.isAvailable()) {
      return res.status(400).json({
        success: false,
        error: 'No LLM providers configured. Set up Ollama, or add DeepSeek/OpenRouter API keys in .env',
      });
    }

    // Set up SSE headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    // ─── Set Provider from Session Config ─────────────────────────────────
    llm.setSelectedProvider(session.llmConfig);

    // ─── Phase 1: Assemble Context ───────────────────────────────────────

    const systemPrompt = await assembler.assembleSystemPrompt(session);
    const userMessage = await assembler.assembleUserMessage(session, message);

    const messages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      { role: 'user', content: userMessage },
    ];

    // Store user message
    session.chatHistory.push({ role: 'user', content: message });

    // ─── Phase 2: Tool Loop ──────────────────────────────────────────────

    const toolDefinitions = executor.getToolDefinitions();
    let roundCount = 0;
    const maxRounds = 10; // Hard limit to force synthesis
    let assistantContent = '';
    const toolCallHistory: { name: string; args: string }[] = [];
    const toolResultHistory: { name: string; args: string; result: string; isError: boolean }[] = [];

    while (roundCount < maxRounds) {
      roundCount++;

      // Send progress
      res.write(`data: ${JSON.stringify({ type: 'chunk', content: `\n_🔍 Analysis round ${roundCount}/${maxRounds}..._\n\n` })}\n\n`);

      // Call LLM
      const response = await llm.chatComplete(messages, toolDefinitions);

      // Handle content
      if (response.content) {
        assistantContent += response.content;
      }

      // Handle tool calls
      if (response.toolCalls && response.toolCalls.length > 0) {
        for (const toolCall of response.toolCalls) {
          // Track tool call history to detect loops
          toolCallHistory.push({ name: toolCall.name, args: JSON.stringify(toolCall.arguments) });

          // Notify frontend
          res.write(`data: ${JSON.stringify({
            type: 'chunk',
            content: `_🔧 Calling ${toolCall.name}..._\n`,
          })}\n\n`);

          // Execute
          const result = await executor.executeTool(toolCall, sessionId);
          const isError = /^\s*Error:/i.test(result.result || '');
          toolResultHistory.push({
            name: toolCall.name,
            args: JSON.stringify(toolCall.arguments),
            result: (result.result || '').substring(0, 1200),
            isError,
          });

          if (isError) {
            res.write(`data: ${JSON.stringify({
              type: 'chunk',
              content: `_⚠️ ${toolCall.name} returned an error. Continuing with available evidence..._\n`,
            })}\n\n`);
          }

          // Add assistant message with tool calls
          messages.push({
            role: 'assistant',
            content: response.content || '',
            toolCalls: [toolCall],
          });

          // Add tool result with correct 'tool' role + tool_call_id (OpenAI-compatible)
          messages.push({
            role: 'tool',
            content: result.result.substring(0, 3000), // Truncate for context budget
            tool_call_id: toolCall.id,
          });
        }

        // Anti-loop detection: if queryGraph called 5+ times, or same tool 4+ times, force synthesis
        const queryGraphCount = toolCallHistory.filter(t => t.name === 'queryGraph').length;
        const lastTool = toolCallHistory[toolCallHistory.length - 1];
        const sameToolRepeats = lastTool
          ? toolCallHistory.filter(t => t.name === lastTool.name && t.args === lastTool.args).length
          : 0;

        if (queryGraphCount >= 5 || sameToolRepeats >= 3) {
          // Force break out of loop — go to synthesis phase
          res.write(`data: ${JSON.stringify({ type: 'chunk', content: '\n_⚠️ Loop detected. Forcing synthesis..._\n\n' })}\n\n`);
          break;
        }

        continue;
      }

      // Natural language response — stream it
      if (response.content) {
        for (const char of response.content) {
          res.write(`data: ${JSON.stringify({ type: 'chunk', content: char })}\n\n`);
        }
      }
      break;
    }

    // ─── ALWAYS Force Synthesis ────────────────────────────────────────────
    // The tool loop never produces a real answer — assistantContent is just
    // fragmented thinking from each tool round. We ALWAYS make a final
    // synthesis call with a clean context to get a coherent response.

    res.write(`data: ${JSON.stringify({ type: 'chunk', content: '\n_📝 Synthesizing findings..._\n\n' })}\n\n`);

    // Build a clean synthesis prompt that summarizes all tool results
    // without the problematic conversation history
    const synthesisMessages: ChatMessage[] = [
      { role: 'system', content: systemPrompt },
      {
        role: 'user',
        content: `${message}\n\n---\n\nYou have already gathered the following data through tool calls (do NOT call any more tools):\n\n${toolCallHistory.map((t, i) => `${i + 1}. ${t.name}: ${t.args.substring(0, 200)}`).join('\n')}\n\nTool results:\n${toolResultHistory.map((t, i) => `${i + 1}. ${t.name} => ${t.result.substring(0, 400)}`).join('\n\n')}\n\nCRITICAL RULES FOR SYNTHESIS:\n- Use ONLY the tool results shown above as evidence.\n- If a tool result starts with \"Error:\", treat that evidence as unavailable.\n- Do NOT invent packet numbers, IPs, MACs, or protocol findings not present in tool results.\n- If evidence is insufficient due to tool errors, explicitly say \"insufficient evidence due to tool execution errors\".\n\nPlease write a clear summary of findings. List any compliance violations with specific evidence (packet numbers, IPs, protocols). If no violations were found after reasonable exploration, state that clearly.`,
      },
    ];

    try {
      const finalResponse = await llm.chatComplete(synthesisMessages, []);
      if (finalResponse.content && finalResponse.content.trim().length > 10) {
        assistantContent = finalResponse.content;
        for (const char of assistantContent) {
          res.write(`data: ${JSON.stringify({ type: 'chunk', content: char })}\n\n`);
        }
      } else {
        throw new Error('Empty synthesis response');
      }
    } catch (err: any) {
      console.error('[Chat] Synthesis failed:', err.message);
      assistantContent = 'Analysis completed. I explored the capture using multiple tools (graph analysis, packet filters, expert info) but was unable to produce a detailed synthesis. Key observations from exploration:\n\n' +
        toolCallHistory.slice(0, 6).map((t, i) => `- ${t.name}: ${t.args.substring(0, 120)}`).join('\n') +
        '\n\nFor more detailed analysis, try uploading a security policy document or ask a specific question like "Show me HTTP traffic" or "Find TLS 1.0 handshakes".';
      for (const char of assistantContent) {
        res.write(`data: ${JSON.stringify({ type: 'chunk', content: char })}\n\n`);
      }
    }

    // Store assistant response
    session.chatHistory.push({ role: 'assistant', content: assistantContent || '(Analysis completed)' });
    session.updatedAt = new Date().toISOString();
    store.updateSession(session);

    res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`);
    res.end();
  } catch (err: any) {
    console.error('[Chat] Error:', err);
    try {
      res.write(`data: ${JSON.stringify({ type: 'error', error: err.message })}\n\n`);
      res.end();
    } catch {
      res.status(500).json({ success: false, error: err.message });
    }
  }
});

// ─── LLM Status ────────────────────────────────────────────────────────────

chatRouter.get('/status', (_req: Request, res: Response) => {
  res.json({
    success: true,
    data: {
      available: llm.isAvailable(),
      providers: llm.getStatus(),
    },
  });
});
