import { useState } from 'react';
import { useStore } from '../../store';

/**
 * Session Reset Button — Clear current session memory without deleting files.
 * Positioned in Header for easy access.
 */
export function SessionResetButton() {
  const { sessionId, resetFindings, resetChatHistory } = useStore();
  const [isResetting, setIsResetting] = useState(false);

  const handleResetSession = async () => {
    if (!confirm('Reset current session? This will clear chat history and findings but keep your uploaded files.')) {
      return;
    }

    setIsResetting(true);

    try {
      const response = await fetch(`/api/session/controls/reset/${sessionId}`, {
        method: 'POST',
      });

      const result = await response.json();

      if (result.success) {
        // Clear frontend state
        resetChatHistory();
        resetFindings();

        alert(`Session reset successfully.\n\nPreserved:\n- ${result.data.preserved.captureFiles} capture file(s)\n- Policy: ${result.data.preserved.hasPolicy ? 'Yes' : 'No'}\n- LLM settings`);
      } else {
        alert('Failed to reset session: ' + result.error);
      }
    } catch (err: any) {
      alert('Error resetting session: '  + err.message);
    } finally {
      setIsResetting(false);
    }
  };

  return (
    <button
      onClick={handleResetSession}
      disabled={isResetting}
      className="px-3 py-1.5 text-xs font-medium bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-600/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
      title="Reset session — clear chat and findings, keep files"
    >
      {isResetting ? (
        <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
          <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth={4} />
          <path
            className="opacity-75"
            fill="currentColor"
            d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"
          />
        </svg>
      ) : (
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
        </svg>
      )}
      Reset Session
    </button>
  );
}
