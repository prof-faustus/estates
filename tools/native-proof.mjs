// One-command NATIVE proof. Orchestrates the full native-parity gate end-to-end:
//   1. start the REAL HTTP relay + drive a REAL two-peer game over it (live-spectate.ts)
//   2. wait for its on-disk manifest (channel + the web's canonical state hash)
//   3. build + run Estates.Conformance, pointing it at that manifest, so the native
//      client reads the live channel back over HTTP and replays it to the SAME hash
//   4. stop the relay (no zombie processes left behind)
// Exits non-zero if the native conformance fails any layer.
//
// Usage: node tools/native-proof.mjs   (needs the .NET 8 SDK on PATH or at D:\dotnet)
import { spawn, spawnSync } from 'node:child_process';
import { existsSync, rmSync, readFileSync } from 'node:fs';
import { setTimeout as sleep } from 'node:timers/promises';
import { join, resolve } from 'node:path';

const ROOT = resolve(import.meta.dirname, '..');
const MANIFEST = join(ROOT, 'apps', 'native', 'Estates.Conformance', 'live-spectate.json');
const PORT = process.env.RELAY_PORT ?? '8799';
const CHANNEL = process.env.RELAY_CHANNEL ?? 'native-proof-' + Math.random().toString(16).slice(2, 10);
const isWin = process.platform === 'win32';

// locate the .NET SDK: PATH, then the known host install at D:\dotnet
function dotnetCmd() {
  const probe = spawnSync(isWin ? 'where' : 'which', ['dotnet'], { encoding: 'utf8' });
  if (probe.status === 0 && probe.stdout.trim()) return 'dotnet';
  for (const p of ['D:\\dotnet\\dotnet.exe', '/d/dotnet/dotnet']) if (existsSync(p)) return p;
  throw new Error('dotnet SDK not found on PATH or at D:\\dotnet');
}

rmSync(MANIFEST, { force: true });

console.log(`[native-proof] starting relay+game on :${PORT} channel '${CHANNEL}'…`);
const harness = spawn(process.execPath, ['--experimental-strip-types', join(ROOT, 'tools', 'live-spectate.ts')], {
  cwd: ROOT,
  stdio: 'inherit',
  env: { ...process.env, RELAY_PORT: PORT, RELAY_CHANNEL: CHANNEL },
});

let code = 1;
try {
  for (let i = 0; i < 60 && !existsSync(MANIFEST); i++) await sleep(500);
  if (!existsSync(MANIFEST)) throw new Error('harness never produced live-spectate.json');
  const m = JSON.parse(readFileSync(MANIFEST, 'utf8'));
  console.log(`[native-proof] live game up: ${m.frames} frames, turn ${m.turnIndex}, web hash ${m.stateHash.slice(0, 16)}…`);

  const dotnet = dotnetCmd();
  console.log('[native-proof] building + running Estates.Conformance…');
  const run = spawnSync(dotnet, ['run', '-c', 'Release'], {
    cwd: join(ROOT, 'apps', 'native', 'Estates.Conformance'),
    stdio: 'inherit',
    env: { ...process.env, ESTATES_LIVE_SPECTATE: MANIFEST, DOTNET_CLI_HOME: process.env.DOTNET_CLI_HOME ?? '/tmp/dh' },
  });
  code = run.status ?? 1;
} finally {
  harness.kill('SIGTERM');
  await sleep(300);
  if (!harness.killed) harness.kill('SIGKILL');
  rmSync(MANIFEST, { force: true });
}

console.log(code === 0 ? '[native-proof] PASS — native conformance green (incl. live HTTP spectate)' : `[native-proof] FAIL — conformance exit ${code}`);
process.exit(code);
