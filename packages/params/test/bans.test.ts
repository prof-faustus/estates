import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, writeFileSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

// packages/params/test -> packages/params -> packages -> <root>
const ROOT = join(fileURLToPath(new URL('.', import.meta.url)), '..', '..', '..');
const LINT = join(ROOT, 'tools', 'lint-bans.ts');

function runLint() {
  return spawnSync(process.execPath, ['--experimental-strip-types', LINT], {
    cwd: ROOT, encoding: 'utf8', shell: false,
  });
}

test('lint-bans passes on the clean tree (the gate is green)', () => {
  const r = runLint();
  assert.equal(r.status, 0, `lint-bans should pass; stderr:\n${r.stderr}`);
});

test('lint-bans FAILS on an OP_RETURN violation', () => {
  const dir = join(ROOT, 'scratch');
  const probe = join(dir, '__ban_probe_opreturn__.ts');
  mkdirSync(dir, { recursive: true });
  writeFileSync(probe, 'export const x = OP_RETURN;\n', 'utf8');
  try {
    const r = runLint();
    assert.equal(r.status, 1, 'lint-bans must exit 1 on OP_RETURN');
    assert.match(r.stderr, /OP_RETURN/);
  } finally {
    rmSync(probe, { force: true });
  }
});

test('lint-bans FAILS on a branded string in content', () => {
  const dir = join(ROOT, 'scratch');
  const probe = join(dir, '__ban_probe_brand__.json');
  mkdirSync(dir, { recursive: true });
  writeFileSync(probe, '{ "name": "Boardwalk" }\n', 'utf8');
  try {
    const r = runLint();
    assert.equal(r.status, 1, 'lint-bans must exit 1 on a branded string');
    assert.match(r.stderr, /branded string/);
  } finally {
    rmSync(probe, { force: true });
  }
});
