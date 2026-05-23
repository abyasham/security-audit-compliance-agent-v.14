import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useStore } from '../../store';

export function PcapUpload() {
  const { uploadAndParsePcap, captureFile, isParsing } = useStore();
  const [uploadError, setUploadError] = useState<string | null>(null);

  const onDrop = useCallback(async (accepted: File[]) => {
    if (accepted.length > 0) {
      setUploadError(null);
      try {
        await uploadAndParsePcap(accepted[0]);
      } catch (err: any) {
        const msg = err.message || String(err);
        if (msg.includes('tshark') || msg.includes('not recognized')) {
          setUploadError(
            '⚠️ **tshark not found** — Wireshark/tshark is required to parse packet captures.\n\n' +
            '**To fix:**\n' +
            '1. Download & install Wireshark from https://www.wireshark.org/download.html\n' +
            '2. Ensure "Install tshark" is checked during installation\n' +
            '3. Restart SACA server\n\n' +
            'Or set TSHARK_PATH in backend/.env to point to your tshark.exe'
          );
        } else {
          setUploadError(msg);
        }
      }
    }
  }, [uploadAndParsePcap]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/octet-stream': ['.pcap', '.pcapng', '.cap', '.pcpap'],
    },
    maxFiles: 1,
    disabled: isParsing || !!captureFile,
  });

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
        📡 Network Capture
        {isParsing && <span className="text-sm text-yellow-400 animate-pulse">Parsing...</span>}
      </h2>

      {/* tshark error with install instructions */}
      {uploadError && (
        <div className="mb-3 bg-red-900/30 border border-red-800 rounded-lg p-4 text-sm">
          <pre className="text-red-300 whitespace-pre-wrap font-sans">{uploadError}</pre>
        </div>
      )}

      {captureFile ? (
        <div className="bg-green-900/20 border border-green-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-green-300">
            <span>✅</span>
            <span className="font-medium">{captureFile.name}</span>
          </div>
          {captureFile.summary ? (
            <div className="mt-2 text-sm text-green-400/80 space-y-1">
              <p>📦 {captureFile.summary.packetCount.toLocaleString()} packets</p>
              <p>🔗 {captureFile.summary.tcpStreamCount} TCP streams</p>
              <p>⏱ {captureFile.summary.durationSeconds.toFixed(1)}s duration</p>
            </div>
          ) : (
            <p className="mt-2 text-sm text-yellow-400">⏳ Parse results loading...</p>
          )}
        </div>
      ) : (
        <div
          {...getRootProps()}
          className={`border-2 border-dashed rounded-xl p-8 text-center cursor-pointer transition-colors ${
            isDragActive
              ? 'border-saca-500 bg-saca-500/10'
              : 'border-gray-700 hover:border-gray-500 bg-gray-800/50'
          }`}
        >
          <input {...getInputProps()} />
          <div className="text-4xl mb-3">📁</div>
          {isDragActive ? (
            <p className="text-saca-300 font-medium">Drop pcap file here...</p>
          ) : (
            <>
              <p className="text-gray-300 font-medium mb-1">
                Drop a pcap file here, or click to browse
              </p>
              <p className="text-gray-500 text-sm">Supports .pcap .pcapng .cap .pcpap</p>
              <p className="text-gray-600 text-xs mt-2">Requires tshark (Wireshark CLI) installed</p>
            </>
          )}
        </div>
      )}
    </div>
  );
}
