// The live table produces a signed ONE-GAME KEY MANIFEST binding every seated
// player's key to this game's id — the auditable artifact that lets cross-game key
// reuse be rejected by the audit layer.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import { genIdentity, gameIdentityFrom, signData } from '@estates/channel';
import { verifyManifest, verifyNoCrossGameReuse, buildManifest, hashHex } from '@estates/keylife';
import { NetTable, type NetworkMode } from '../src/index.ts';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
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

test('the host BROADCASTS the manifest at start; every peer verifies the SAME live manifest', () => {
  const relay = new InMemoryRelay();
  const masterA = new Uint8Array(32).fill(5); const masterB = new Uint8Array(32).fill(6);
  const alice = new NetTable(relay, 'alice', () => {}, { identity: gameIdentityFrom(masterA, GID_A), gameId: GID_A });
  const bob = new NetTable(relay, 'bob', () => {}, { identity: gameIdentityFrom(masterB, GID_A), gameId: GID_A });
  alice.connect(); bob.connect();
  alice.createTable(2, 'regtest' as NetworkMode);
  alice.joinSeat(); bob.joinSeat();
  alice.start(); // host broadcasts start + the signed manifest

  // BOTH peers (not just the host) end up with the SAME verified live manifest
  const ma = alice.verifiedManifest();
  const mb = bob.verifiedManifest();
  assert.ok(ma, 'host has the live manifest');
  assert.ok(mb, 'the OTHER peer verified the broadcast manifest too');
  assert.equal(ma!.gameId, GID_A);
  assert.deepEqual(ma!.entries, mb!.entries, 'both peers verified the identical manifest');
  assert.ok(verifyManifest(mb!).ok, 'the peer-verified manifest is valid');
});

test('a FORGED manifest whose seat keys differ from the committed seat map is NOT accepted', () => {
  const relay = new InMemoryRelay();
  const host = gameIdentityFrom(new Uint8Array(32).fill(5), GID_A);
  const alice = new NetTable(relay, 'alice', () => {}, { identity: host, gameId: GID_A });
  const bob = new NetTable(relay, 'bob', () => {}, { identity: gameIdentityFrom(new Uint8Array(32).fill(6), GID_A), gameId: GID_A });
  alice.connect(); bob.connect();
  alice.createTable(2, 'regtest' as NetworkMode);
  alice.joinSeat(); bob.joinSeat();
  // the host publishes a manifest binding STRANGER keys instead of the seated ones
  const stranger = genIdentity(); const auth = genIdentity();
  const forged = buildManifest(GID_A, 'estates-table-v1', hashHex(new TextEncoder().encode('estates-params:1')), [
    { purpose: 'genesis', pub: toHex(auth.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: toHex(stranger.signPub), keyType: 'ed25519', seat: 0 },
    { purpose: 'seat', pub: toHex(genIdentity().signPub), keyType: 'ed25519', seat: 1 },
  ], auth.signPriv, toHex(auth.signPub));
  const signPub = toHex(host.signPub);
  const msg = { kind: 'manifest', m: forged };
  const sig = toHex(signData(enc({ ...msg, signPub }), host.signPriv));
  relay.publish(enc({ ...msg, id: 'forged-manifest', signPub, sig }));
  // peers must NOT accept it — its seat keys don't match the committed seat map
  assert.equal(bob.verifiedManifest(), null, 'a manifest not matching the seat map is rejected');
});
