import { useCallback, useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { useStore } from '../../store';

export function PolicyUpload() {
  const { uploadAndParsePolicy, policy, isParsing } = useStore();
  const [uploadError, setUploadError] = useState<string | null>(null);

  const onDrop = useCallback(async (accepted: File[]) => {
    if (accepted.length > 0) {
      setUploadError(null);
      try {
        await uploadAndParsePolicy(accepted[0]);
      } catch (err: any) {
        setUploadError(err.message || String(err));
      }
    }
  }, [uploadAndParsePolicy]);

  const { getRootProps, getInputProps, isDragActive } = useDropzone({
    onDrop,
    accept: {
      'application/pdf': ['.pdf'],
      'application/vnd.openxmlformats-officedocument.wordprocessingml.document': ['.docx', '.doc'],
      'application/json': ['.json'],
      'text/plain': ['.txt', '.yaml', '.yml'],
    },
    maxFiles: 1,
    disabled: isParsing || !!policy,
  });

  return (
    <div className="card">
      <h2 className="text-lg font-semibold mb-3 flex items-center gap-2">
        📋 Security Policy
        {isParsing && <span className="text-sm text-yellow-400 animate-pulse">Parsing...</span>}
      </h2>

      {uploadError && (
        <div className="mb-3 bg-red-900/30 border border-red-800 rounded-lg p-4 text-sm text-red-300">
          ⚠ {uploadError}
        </div>
      )}

      {policy ? (
        <div className="bg-green-900/20 border border-green-800 rounded-lg p-4">
          <div className="flex items-center gap-2 text-green-300">
            <span>✅</span>
            <span className="font-medium">{policy.policyName}</span>
          </div>
          <div className="mt-2 text-sm text-green-400/80 space-y-1">
            <p>📄 Format: {policy.sourceFormat.toUpperCase()}</p>
            {policy.rules.length > 0 ? (
              <p>📜 {policy.rules.length} policy rules extracted</p>
            ) : (
              <>
                <p>📜 Policy text extracted ({policy.rawText?.length || 0} characters)</p>
                <p className="text-yellow-400 text-xs">
                  ⚡ Rules will be extracted by the LLM during analysis. For now, the full policy text
                  will be provided to the AI for context-aware compliance checking.
                </p>
              </>
            )}
            {policy.version && <p>📌 Version: {policy.version}</p>}
          </div>
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
          <div className="text-4xl mb-3">📄</div>
          {isDragActive ? (
            <p className="text-saca-300 font-medium">Drop policy file here...</p>
          ) : (
            <>
              <p className="text-gray-300 font-medium mb-1">
                Drop a security policy document
              </p>
              <p className="text-gray-500 text-sm">Supports PDF, DOCX, JSON, YAML, TXT</p>
            </>
          )}
        </div>
      )}
    </div>
  );
}
