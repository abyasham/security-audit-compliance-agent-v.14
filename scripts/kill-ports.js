const { execSync } = require('child_process');

function killPort(port) {
  try {
    const result = execSync(`netstat -ano | findstr :${port}`, { encoding: 'utf-8', windowsHide: true });
    const lines = result.trim().split('\n');
    const killed = new Set();
    for (const line of lines) {
      const parts = line.trim().split(/\s+/);
      const pid = parts[parts.length - 1];
      if (pid && !isNaN(parseInt(pid)) && !killed.has(pid)) {
        killed.add(pid);
        try {
          execSync(`taskkill /F /PID ${pid}`, { windowsHide: true });
          console.log(`[kill-ports] Killed PID ${pid} on port ${port}`);
        } catch (e) {
          // ignore
        }
      }
    }
  } catch (e) {
    // no process on this port
  }
}

killPort(3001);
killPort(5173);
killPort(5174);
console.log('[kill-ports] Done');
