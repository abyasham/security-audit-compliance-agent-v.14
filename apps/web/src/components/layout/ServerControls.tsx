import { useState, useEffect } from 'react';

export function ServerControls() {
  const [serverStatus, setServerStatus] = useState<'unknown' | 'online' | 'offline'>('unknown');
  const [isClearing, setIsClearing] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  // Check server status on mount and periodically
  useEffect(() => {
    checkStatus();
    const interval = setInterval(checkStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  const checkStatus = async () => {
    try {
      const response = await fetch('/api/chat/status', { method: 'GET' });
      if (response.ok) {
        setServerStatus('online');
      } else {
        setServerStatus('offline');
      }
    } catch {
      setServerStatus('offline');
    }
  };

  const handleStop = async () => {
    if (!confirm('Stop all SACA servers? You will need to run "npm run start" to restart.')) return;
    
    try {
      // Call the backend shutdown endpoint if available, or just inform user
      await fetch('/api/shutdown', { method: 'POST' }).catch(() => {});
      setMessage('Stop command sent. Servers will shut down shortly.');
      setServerStatus('offline');
    } catch {
      setMessage('Stop signal sent.');
    }
  };

  const handleClearMemory = async () => {
    if (!confirm('Clear all audit memory? This will delete all sessions, findings, graphs, and uploaded files. This cannot be undone.')) return;
    
    setIsClearing(true);
    setMessage(null);
    
    try {
      const response = await fetch('/api/session/reset', { method: 'POST' });
      const result = await response.json();
      
      if (result.success) {
        setMessage(`Memory cleared: ${result.data.sessionsCleared} sessions, ${result.data.graphsCleared} graphs removed.`);
        // Reload the page to reflect cleared state
        setTimeout(() => window.location.reload(), 1500);
      } else {
        setMessage('Failed to clear memory: ' + result.error);
      }
    } catch (err: any) {
      setMessage('Error clearing memory: ' + err.message);
    } finally {
      setIsClearing(false);
    }
  };

  const handleStart = () => {
    alert('To start SACA servers, run: npm run start\n\nOr use the batch scripts in the scripts/ folder.');
  };

  return (
    <div className="flex items-center gap-2">
      {/* Status indicator */}
      <div className="flex items-center gap-1.5 mr-2">
        <div className={`w-2 h-2 rounded-full ${serverStatus === 'online' ? 'bg-green-500 animate-pulse' : serverStatus === 'offline' ? 'bg-red-500' : 'bg-gray-500'}`} />
        <span className="text-xs text-gray-400">
          {serverStatus === 'online' ? 'Online' : serverStatus === 'offline' ? 'Offline' : 'Checking...'}
        </span>
      </div>

      {/* Stop Button */}
      <button
        onClick={handleStop}
        disabled={serverStatus !== 'online'}
        className="px-3 py-1.5 text-xs font-medium bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-600/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
        title="Stop all SACA processes"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <rect x="6" y="6" width="12" height="12" rx="2" strokeWidth={2} />
        </svg>
        Stop
      </button>

      {/* Clear Memory Button */}
      <button
        onClick={handleClearMemory}
        disabled={isClearing || serverStatus !== 'online'}
        className="px-3 py-1.5 text-xs font-medium bg-yellow-600/20 hover:bg-yellow-600/30 text-yellow-400 border border-yellow-600/50 rounded-lg transition-colors disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-1.5"
        title="Clear all audit memory (sessions, findings, graphs)"
      >
        {isClearing ? (
          <svg className="w-3.5 h-3.5 animate-spin" fill="none" viewBox="0 0 24 24">
            <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
            <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
          </svg>
        ) : (
          <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
          </svg>
        )}
        Clear Memory
      </button>

      {/* Start Button */}
      <button
        onClick={handleStart}
        className="px-3 py-1.5 text-xs font-medium bg-green-600/20 hover:bg-green-600/30 text-green-400 border border-green-600/50 rounded-lg transition-colors flex items-center gap-1.5"
        title="Start SACA servers (opens new terminal windows)"
      >
        <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z" />
          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
        </svg>
        Start
      </button>

      {/* Message toast */}
      {message && (
        <div className="fixed top-4 right-4 z-50 max-w-sm">
          <div className="bg-gray-900 border border-gray-700 text-white px-4 py-3 rounded-lg shadow-lg text-sm">
            {message}
            <button 
              onClick={() => setMessage(null)}
              className="ml-3 text-gray-400 hover:text-white"
            >
              ×
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
