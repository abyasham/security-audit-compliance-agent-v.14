import path from 'path';
import fs from 'fs';

/**
 * Load .env from repo root ONLY.
 * All API keys belong in one place: c:\saca\saca14\.env
 */
function loadEnv(): void {
  const envPath = path.resolve(__dirname, '..', '..', '..', '.env');  // repo root
  if (!fs.existsSync(envPath)) {
    console.warn(`[Config] No .env found at ${envPath}`);
    return;
  }

  const content = fs.readFileSync(envPath, 'utf-8');
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const eqIdx = trimmed.indexOf('=');
    if (eqIdx === -1) continue;
    const key = trimmed.substring(0, eqIdx).trim();
    let value = trimmed.substring(eqIdx + 1).trim();
    // Remove surrounding quotes
    if ((value.startsWith('"') && value.endsWith('"')) ||
        (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1);
    }
    if (!process.env[key]) {
      process.env[key] = value;
    }
  }
}

// Load .env before anything else
loadEnv();

export interface AppConfig {
  port: number;
  uploadDir: string;
  dataDir: string;
  maxFileSize: number; // bytes
  tsharkPath: string;
  pythonCoreUrl: string;
  llmConfig: {
    ollama: { baseUrl: string; model: string };
    deepseek: { apiKey: string; model: string };
    openrouter: { apiKey: string; model: string };
    openrouter2: { apiKey: string; model: string };
    openai: { apiKey: string; model: string };
    kimi: { apiKey: string; model: string };
    nvidia: { apiKey: string; model: string };
  };
}

function loadConfig(): AppConfig {
  const uploadDir = path.resolve(__dirname, '..', 'uploads');
  const dataDir = path.resolve(__dirname, '..', 'data');

  // Ensure directories exist
  for (const dir of [uploadDir, dataDir]) {
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  return {
    port: parseInt(process.env.PORT || '3001', 10),
    uploadDir,
    dataDir,
    maxFileSize: parseInt(process.env.MAX_FILE_SIZE || '104857600', 10), // 100MB
    tsharkPath: process.env.TSHARK_PATH || '',
    pythonCoreUrl: process.env.PYTHON_CORE_URL || 'http://localhost:8000',
    llmConfig: {
      ollama: {
        baseUrl: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
        model: process.env.OLLAMA_MODEL || 'deepseek-r1:14b',
      },
      deepseek: {
        apiKey: process.env.DEEPSEEK_API_KEY || '',
        model: process.env.DEEPSEEK_MODEL || 'deepseek-chat',
      },
      openrouter: {
        apiKey: process.env.OPENROUTER1_API_KEY || process.env.OPENROUTER_API_KEY || '',
        model: process.env.OPENROUTER1_MODEL || process.env.OPENROUTER_MODEL || 'google/gemma-4-31b-it',
      },
      openrouter2: {
        apiKey: process.env.OPENROUTER2_API_KEY || '',
        model: process.env.OPENROUTER2_MODEL || 'openrouter/owl-alpha',
      },
      openai: {
        apiKey: process.env.OPENAI_API_KEY || '',
        model: process.env.OPENAI_MODEL || 'gpt-4.1-mini-2025-04-14',
      },
      kimi: {
        apiKey: process.env.KIMI_API_KEY || '',
        model: process.env.KIMI_MODEL || 'kimi-k2.5',
      },
      nvidia: {
        apiKey: process.env.NVIDIA_API_KEY || '',
        model: process.env.NVIDIA_MODEL || 'mistralai/mistral-large-3-675b-instruct-2512',
      },
    },
  };
}

export const config = loadConfig();
