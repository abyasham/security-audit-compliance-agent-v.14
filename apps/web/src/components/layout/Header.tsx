import { ServerControls } from './ServerControls';

export function Header() {
  return (
    <header className="border-b border-gray-800 bg-gray-900/50 backdrop-blur-sm">
      <div className="container mx-auto px-4 py-3 max-w-7xl flex items-center justify-between">
        <div className="flex items-center gap-3">
          <img
            src="/saca.jpg"
            alt="SACA Logo"
            className="h-10 w-auto object-contain rounded"
          />
          <div>
            <h1 className="text-lg font-bold text-white tracking-tight">
              SACA
            </h1>
            <p className="text-xs text-gray-500 -mt-0.5">
              Security Audit Compliance Agent
            </p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => window.location.reload()}
            className="px-3 py-1.5 text-xs font-medium bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-600/50 rounded-lg transition-colors flex items-center gap-1.5"
            title="Reset session — clear chat and findings, keep files"
          >
            <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
            </svg>
            Reset
          </button>
          <div className="w-px h-6 bg-gray-700/50" />
          <ServerControls />
        </div>
      </div>
    </header>
  );
}
