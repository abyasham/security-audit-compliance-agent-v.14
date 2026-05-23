"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.config = void 0;
const path_1 = __importDefault(require("path"));
const fs_1 = __importDefault(require("fs"));
/**
 * Load .env from repo root ONLY.
 * All API keys belong in one place: c:\saca\saca14\.env
 */
function loadEnv() {
    const envPath = path_1.default.resolve(__dirname, '..', '..', '..', '.env'); // repo root
    if (!fs_1.default.existsSync(envPath)) {
        console.warn(`[Config] No .env found at ${envPath}`);
        return;
    }
    const content = fs_1.default.readFileSync(envPath, 'utf-8');
    for (const line of content.split('\n')) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('#'))
            continue;
        const eqIdx = trimmed.indexOf('=');
        if (eqIdx === -1)
            continue;
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
function loadConfig() {
    const uploadDir = path_1.default.resolve(__dirname, '..', 'uploads');
    const dataDir = path_1.default.resolve(__dirname, '..', 'data');
    // Ensure directories exist
    for (const dir of [uploadDir, dataDir]) {
        if (!fs_1.default.existsSync(dir)) {
            fs_1.default.mkdirSync(dir, { recursive: true });
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
exports.config = loadConfig();
//# sourceMappingURL=config.js.map