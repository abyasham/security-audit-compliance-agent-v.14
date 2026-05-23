/**
 * Minimal TsharkRunner stub — retained for capture route compatibility.
 *
 * In v14, all heavy pcap analysis is done by Python Core (pyshark).
 * This stub provides basic tshark CLI access for the capture route's
 * packet inspection / summary endpoints.
 */
export declare class TsharkRunner {
    private detectedPath;
    private attempted;
    get tsharkPath(): string;
    isAvailable(): boolean;
    getStatus(): {
        path: string;
        available: boolean;
    };
    detectTshark(): Promise<string | null>;
    private detectSync;
    getCaptureSummary(filePath: string): Promise<any>;
    getConversations(filePath: string, protocol: string): Promise<string>;
    getPacketRange(filePath: string, start: number, end: number, filter?: string): Promise<string>;
    getExpertInfo(filePath: string, _severity: string): Promise<string>;
    applyFilter(filePath: string, displayFilter: string, maxPackets?: number): Promise<string>;
    followStream(filePath: string, streamId: number, _mode?: string): Promise<string>;
    getStreamDetail(filePath: string, streamIndex: number): Promise<string>;
    getProtocolHierarchy(filePath: string): Promise<string>;
    runTshark(filePath: string, extraArgs: string): Promise<string>;
}
//# sourceMappingURL=tsharkRunner.d.ts.map