/**
 * ci.ts — ESTATES CI pipeline. Each step must pass or the build fails.
 * Mirrors bsv-poker's tools/ci.ts shape. Run: node --experimental-strip-types tools/ci.ts
 */
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..');

const TSC = join(ROOT, 'node_modules', 'typescript', 'bin', 'tsc');

// Every step runs through the Node executable directly (no shell) so paths
// with spaces (e.g. "C:\Program Files\nodejs\node.exe") are never re-split.
const steps: { name: string; args: string[]; cmd?: string; shell?: boolean }[] = [
  { name: 'static bans (OP_RETURN / CLTV / CSV / branded)', args: ['--experimental-strip-types', join('tools', 'lint-bans.ts')] },
  { name: 'typecheck', args: [TSC, '-p', 'tsconfig.json', '--noEmit'] },
  { name: 'tests', args: ['--test', '--experimental-strip-types', 'packages/**/test/**/*.test.ts'] },
  // web client bundle must compile (audit #10) — the desktop UI's frontend.
  { name: 'web client build', cmd: 'pnpm', args: ['--filter', '@estates/client-web', 'build'], shell: true },
];

let failed = false;
for (const step of steps) {
  console.log(`\n=== ${step.name} ===`);
  const r = spawnSync(step.cmd ?? process.execPath, step.args, { cwd: ROOT, stdio: 'inherit', shell: step.shell ?? false });
  if (r.status !== 0) {
    console.error(`✘ step failed: ${step.name}`);
    failed = true;
    break;
  }
}

if (failed) process.exit(1);
console.log('\n✓ CI green.');
