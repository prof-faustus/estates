// The live table produces a signed ONE-GAME KEY MANIFEST binding every seated
// player's key to this game's id — the auditable artifact that lets cross-game key
// reuse be rejected by the audit layer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import { genIdentity, gameIdentityFrom } from '@estates/channel';
import { verifyManifest, verifyNoCrossGameReuse, buildManifest, hashHex } from '@estates/keylife';
import { NetTable, type NetworkMode } from '../src/index.ts';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const GID_A = 'a1'.repeat(32);
const GID_B = 'b2'.repeat(32);

function startedGame(gameId: string, masterA: Uint8Array, masterB: Uint8Array): NetTable {
  const relay = new InMemoryRelay();
  // PER-GAME seat keys: each player derives a distinct key for THIS game from their
  // own master (channel.gameIdentityFrom), so the same wallet never reuses a key.
  const alice = new NetTable(relay, 'alice', () => {}, { identity: gameIdentityFrom(masterA, gameId), gameId });
  const bob = new NetTable(relay, 'bob', () => {}, { identity: gameIdentityFrom(masterB, gameId), gameId });
  alice.connect(); bob.connect();
  alice.createTable(2, 'regtest' as NetworkMode);
  alice.joinSeat(); bob.joinSeat();
  alice.start();
  return alice;
}

test('a started game yields a signed key manifest that verifies and binds each seat key to the game id', () => {
  const alice = startedGame(GID_A, new Uint8Array(32).fill(1), new Uint8Array(32).fill(2));
  const m = alice.gameKeyManifest();
  assert.ok(m, 'host produces a manifest');
  assert.ok(verifyManifest(m).ok, 'the manifest verifies (signed by the host authority)');
  assert.equal(m!.gameId, GID_A);
  // it binds exactly the two seat keys
  const seatKeys = m!.entries.filter((e) => e.purpose === 'seat').map((e) => e.pub).sort();
  assert.equal(seatKeys.length, 2);
});

test('a non-host peer does not produce a manifest', () => {
  const relay = new InMemoryRelay();
  const alice = new NetTable(relay, 'alice', () => {}, { identity: gameIdentityFrom(new Uint8Array(32).fill(1), GID_A), gameId: GID_A });
  const bob = new NetTable(relay, 'bob', () => {}, { identity: gameIdentityFrom(new Uint8Array(32).fill(2), GID_A), gameId: GID_A });
  alice.connect(); bob.connect();
  alice.createTable(2, 'regtest' as NetworkMode);
  alice.joinSeat(); bob.joinSeat();
  alice.start();
  assert.equal(bob.gameKeyManifest(), null, 'only the host (genesis authority) issues the manifest');
});

test('per-game keys: the SAME wallets in two different games produce manifests with NO cross-game reuse', () => {
  const masterA = new Uint8Array(32).fill(7);
  const masterB = new Uint8Array(32).fill(9);
  const gameA = startedGame(GID_A, masterA, masterB).gameKeyManifest()!;
  const gameB = startedGame(GID_B, masterA, masterB).gameKeyManifest()!;
  // both verify, and because each player used a PER-GAME key, no key spans games
  assert.ok(verifyManifest(gameA).ok && verifyManifest(gameB).ok);
  assert.ok(verifyNoCrossGameReuse([gameA, gameB]).ok, 'per-game keys → no cross-game reuse');
});

test('the legacy game-independent key WOULD be caught as cross-game reuse (why per-game keys matter)', () => {
  // If the same wallet reused ONE game-independent key across two games, the audit
  // rejects it. (This is what gameIdentityFrom prevents.)
  const sharedKey = genIdentity();
  const PH = hashHex(new TextEncoder().encode('p'));
  // two single-seat manifests reusing sharedKey.signPub as seat 0 in BOTH games
  const a1 = genIdentity(); const a2 = genIdentity();
  const A = buildManifest(GID_A, 'v', PH, [
    { purpose: 'genesis', pub: toHex(a1.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: toHex(sharedKey.signPub), keyType: 'ed25519', seat: 0 },
  ], a1.signPriv, toHex(a1.signPub));
  const B = buildManifest(GID_B, 'v', PH, [
    { purpose: 'genesis', pub: toHex(a2.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: toHex(sharedKey.signPub), keyType: 'ed25519', seat: 0 },
  ], a2.signPriv, toHex(a2.signPub));
  assert.equal(verifyNoCrossGameReuse([A, B]).ok, false, 'a reused key across games is rejected');
});
