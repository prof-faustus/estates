/**
 * The committed vector file is the legality SOURCE OF TRUTH. This test re-runs
 * the live engine against every vector's (state, action) and asserts the
 * result still matches the recorded expectation. Any divergence is a blocking
 * defect (an engine change altered legality, or a vector is stale).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { apply } from '@estates/engine';
import { loadParams } from '@estates/params';
import { hashState, type VectorFile } from '../src/index.ts';

const FILE = join(fileURLToPath(new URL('.', import.meta.url)), '..', 'vectors', 'estates.v1.vectors.json');
const file = JSON.parse(readFileSync(FILE, 'utf8')) as VectorFile;

test('vector file is present, versioned, and non-trivial', () => {
  assert.equal(file.params_version, loadParams().params_version);
  assert.ok(file.vectors.length >= 15, `expected >=15 vectors, got ${file.vectors.length}`);
  const ids = new Set(file.vectors.map((v) => v.id));
  assert.equal(ids.size, file.vectors.length, 'vector ids must be unique');
});

for (const v of file.vectors) {
  test(`conformance: ${v.id} — ${v.description}`, () => {
    const r = apply(v.state, v.action);
    if (v.expected.ok) {
      assert.ok(r.ok, `expected success, got rejection ${r.ok ? '' : r.code}`);
      assert.equal(hashState(r.state), v.expected.stateHash, 'resulting state hash diverged from the vector');
    } else {
      assert.ok(!r.ok, 'expected a rejection, engine accepted the action');
      assert.equal(r.code, v.expected.code, 'rejection code diverged from the vector');
    }
  });
}
