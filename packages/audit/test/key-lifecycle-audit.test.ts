// Mandated test: the audit must verify KEY LIFECYCLE — every game key is valid
// for at most one game. A key reused across games makes the audit FAIL.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { genIdentity } from '@estates/channel';
import { buildManifest, hashHex, type KeyEntry, type GameKeyManifest } from '@estates/keylife';
import { auditKeyLifecycle } from '../src/index.ts';

const PARAMS = hashHex(new TextEncoder().encode('estates.v1'));
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

function game(gameId: string): { manifest: GameKeyManifest; seat0: string } {
  const authority = genIdentity(), s0 = genIdentity(), s1 = genIdentity(), card = genIdentity();
  const entries: KeyEntry[] = [
    { purpose: 'genesis', pub: hex(authority.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: hex(s0.signPub), keyType: 'ed25519', seat: 0 },
    { purpose: 'seat', pub: hex(s1.signPub), keyType: 'ed25519', seat: 1 },
    { purpose: 'card', pub: hex(card.pub), keyType: 'secp256k1' },
  ];
  return { manifest: buildManifest(gameId, 'estates-1', PARAMS, entries, authority.signPriv, hex(authority.signPub)), seat0: hex(s0.signPub) };
}

test('a sequence of games with FRESH keys passes the key-lifecycle audit', () => {
  const a = game('a1'.repeat(32));
  const b = game('b2'.repeat(32));
  const c = game('c3'.repeat(32));
  const r = auditKeyLifecycle([a.manifest, b.manifest, c.manifest]);
  assert.ok(r.ok, r.reason);
});

test('the audit FAILS when a key is reused across two games', () => {
  const a = game('a1'.repeat(32));
  // forge game B that reuses game A's seat-0 key (re-signed so B is internally valid)
  const bAuth = genIdentity();
  const bReuse = buildManifest('b2'.repeat(32), 'estates-1', PARAMS, [
    { purpose: 'genesis', pub: hex(bAuth.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: a.seat0, keyType: 'ed25519', seat: 0 }, // reused from game A
  ], bAuth.signPriv, hex(bAuth.signPub));
  const r = auditKeyLifecycle([a.manifest, bReuse]);
  assert.equal(r.ok, false);
  assert.match(r.reason, /reused across games|one game/i);
});

test('the audit FAILS on a tampered/unsigned manifest', () => {
  const a = game('a1'.repeat(32));
  const tampered = { ...a.manifest, entries: [...a.manifest.entries, { purpose: 'seat' as const, pub: hex(genIdentity().signPub), keyType: 'ed25519' as const, seat: 2 }] };
  assert.equal(auditKeyLifecycle([tampered]).ok, false, 'added key without re-signing → manifest invalid');
  assert.equal(auditKeyLifecycle([]).ok, false, 'no manifests → fail');
});

test('auditKeyLifecycle is FAIL-CLOSED on hostile input (never throws)', () => {
  for (const bad of [null, undefined, 'x', [null], [{}], [42]]) {
    let r: unknown = 'unset';
    assert.doesNotThrow(() => { r = auditKeyLifecycle(bad as unknown as GameKeyManifest[]); });
    assert.equal((r as { ok: boolean }).ok, false);
  }
});
