import path from 'path';
import fs from 'fs';

/**
 * Load .env files manually (no dotenv dependency needed).
 */
function loadEnv(): void {
  const envFiles = ['.env', '.env.local'];

  for (const fileName of envFiles) {
    const envPath = path.resolve(__dirname, '..', fileName);
    if (!fs.existsSync(envPath)) continue;

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
}

// Load .env before anything else
loadEnv();

export interface AppConfig {
  port: number;
  uploadDir: string;
  dataDir: string;
  maxFileSize: number; // bytes
  tsharkPath: string;
  llmConfig: {
    ollama: { baseUrl: string; model: string };
    deepseek: { apiKey: string; model: string };
    openrouter: { apiKey: string; model: string };
    openai: { apiKey: string; model: string };
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
        apiKey: process.env.OPENROUTER_API_KEY || '',
        model: process.env.OPENROUTER_MODEL || 'openai/gpt-4o',
      },
      openai: {
        apiKey: process.env.OPENAI_API_KEY || '',
        model: process.env.OPENAI_MODEL || 'gpt-4.1-mini-2025-04-14',
      },
    },
  };
}

export const config = loadConfig();
