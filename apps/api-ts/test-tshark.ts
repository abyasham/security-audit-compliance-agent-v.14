import { TsharkRunner } from './src/services/tsharkRunner';

async function test() {
  const t = new TsharkRunner();
  const f = './uploads/bc3263e8-5ca7-4d3d-8410-8d8df0a10b51.pcap';
  console.log('[TEST] getPacketRange(1, 10) on', f);
  const r = await t.getPacketRange(f, 1, 10);
  console.log('[TEST] Result length:', r.length);
  console.log('[TEST] First 300 chars:\n', r.substring(0, 300));
}

test().catch(console.error);
