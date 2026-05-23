export interface AppConfig {
    port: number;
    uploadDir: string;
    dataDir: string;
    maxFileSize: number;
    tsharkPath: string;
    pythonCoreUrl: string;
    llmConfig: {
        ollama: {
            baseUrl: string;
            model: string;
        };
        deepseek: {
            apiKey: string;
            model: string;
        };
        openrouter: {
            apiKey: string;
            model: string;
        };
        openrouter2: {
            apiKey: string;
            model: string;
        };
        openai: {
            apiKey: string;
            model: string;
        };
        kimi: {
            apiKey: string;
            model: string;
        };
        nvidia: {
            apiKey: string;
            model: string;
        };
    };
}
export declare const config: AppConfig;
//# sourceMappingURL=config.d.ts.map