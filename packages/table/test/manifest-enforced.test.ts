// With a one-game key MANIFEST, the live table seats ONLY manifest-bound per-game
// keys. A stranger / cross-game key cannot claim a seat, so it can never play —
// the whole live game is manifest-scoped (rebuild enforces it, not just a test).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { InMemoryRelay } from '@estates/chat';
import { genIdentity, signData } from '@estates/channel';
import { buildManifest, hashHex, type KeyEntry, type GameKeyManifest } from '@estates/keylife';
import { NetTable, type NetworkMode } from '../src/index.ts';

const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o));
const GID = 'a1'.repeat(32);
const PARAMS = hashHex(new TextEncoder().encode('estates.v1'));

function manifestFor(host: ReturnType<typeof genIdentity>, alice: ReturnType<typeof genIdentity>, bob: ReturnType<typeof genIdentity>): GameKeyManifest {
  const entries: KeyEntry[] = [
    { purpose: 'genesis', pub: toHex(host.signPub), keyType: 'ed25519' },
    { purpose: 'seat', pub: toHex(alice.signPub), keyType: 'ed25519', seat: 0 },
    { purpose: 'seat', pub: toHex(bob.signPub), keyType: 'ed25519', seat: 1 },
  ];
  return buildManifest(GID, 'estates-1', PARAMS, entries, host.signPriv, toHex(host.signPub));
}

// publish a 'seat' claim signed by `id` (as the table's send() would).
function seatClaim(relay: InMemoryRelay, id: ReturnType<typeof genIdentity>, seat: number, name: string): void {
  const signPub = toHex(id.signPub);
  const msg = { kind: 'seat', seat, who: signPub, name, bot: false };
  const sig = toHex(signData(enc({ ...msg, signPub }), id.signPriv));
  relay.publish(enc({ ...msg, id: `seat-${seat}-${name}`, signPub, sig }));
}

test('with a manifest, a STRANGER key cannot claim a seat; only the bound per-game key can', () => {
  const relay = new InMemoryRelay();
  const host = genIdentity();   // genesis authority AND seat 0 (Alice)
  const bob = genIdentity();    // seat 1
  const stranger = genIdentity(); // NOT in the manifest
  const manifest = manifestFor(host, host, bob); // host plays seat 0

  // Alice runs the table with the manifest; she IS seat 0's bound key.
  const alice = new NetTable(relay, 'alice', () => {}, { identity: host, manifest });
  alice.connect();
  alice.createTable(2, 'regtest' as NetworkMode);

  // a stranger tries to grab seat 0 first → must be REJECTED (not the bound key)
  seatClaim(relay, stranger, 0, 'stranger');
  let v = alice.view();
  assert.equal(v.seats.find((s) => s.seat === 0), undefined, 'stranger did NOT get seat 0');

  // the bound seat-0 key (Alice/host) claims it → accepted
  alice.joinSeat();
  v = alice.view();
  assert.equal(v.seats.find((s) => s.seat === 0)?.who, toHex(host.signPub), 'the manifest-bound key holds seat 0');

  // the stranger tries seat 1 too → rejected (only Bob's bound key may)
  seatClaim(relay, stranger, 1, 'stranger2');
  v = alice.view();
  assert.equal(v.seats.find((s) => s.seat === 1), undefined, 'stranger cannot take seat 1 either');

  // Bob's bound key claims seat 1 → accepted
  seatClaim(relay, bob, 1, 'bob');
  v = alice.view();
  assert.equal(v.seats.find((s) => s.seat === 1)?.who, toHex(bob.signPub), 'Bob’s manifest key holds seat 1');
});

test('without a manifest, the legacy seat-claim binding still works (offline, zero game id)', () => {
  const relay = new InMemoryRelay();
  const alice = new NetTable(relay, 'alice', () => {}, { identity: genIdentity() }); // no manifest, no game id
  alice.connect();
  alice.createTable(2, 'regtest' as NetworkMode);
  alice.joinSeat();
  assert.equal(alice.view().seats.length, 1, 'seat claimed without a manifest (offline path)');
});

test('a REAL game (nonzero gameId) is MANDATORY-manifest: a log WITHOUT the manifest refuses to run', () => {
  const relay = new InMemoryRelay();
  const A = new NetTable(relay, 'A', () => {}, { identity: genIdentity(), gameId: GID });
  const B = new NetTable(relay, 'B', () => {}, { identity: genIdentity(), gameId: GID });
  A.connect(); B.connect();
  A.createTable(2, 'regtest' as NetworkMode);
  A.joinSeat(); B.joinSeat();
  A.start();   // broadcasts the start AND the one-game key manifest
  // WITH its manifest, a real game is live.
  assert.equal(A.view().phase, 'playing', 'a real game that carries its manifest runs');

  // strip the manifest frame from the SAME ordered log → a peer rebuilding it must
  // refuse to run the game (the manifest is mandatory for a real gameId).
  const stripped = relay.history().filter((f) => {
    try { return (JSON.parse(new TextDecoder().decode(f)) as { kind?: string }).kind !== 'manifest'; } catch { return true; }
  });
  assert.equal(stripped.length, relay.history().length - 1, 'exactly one manifest frame was present and removed');
  const relay2 = new InMemoryRelay();
  for (const f of stripped) relay2.publish(f);
  const C = new NetTable(relay2, 'C', () => {}, { identity: genIdentity(), gameId: GID });
  C.connect();
  assert.notEqual(C.view().phase, 'playing', 'WITHOUT the manifest, a real game is NOT live (mandatory, fail-closed)');
});

test('start() actually BROADCASTS exactly one valid manifest frame for a real game', () => {
  const relay = new InMemoryRelay();
  const A = new NetTable(relay, 'A', () => {}, { identity: genIdentity(), gameId: GID });
  const B = new NetTable(relay, 'B', () => {}, { identity: genIdentity(), gameId: GID });
  A.connect(); B.connect();
  A.createTable(2, 'regtest' as NetworkMode);
  A.joinSeat(); B.joinSeat();
  A.start();
  const manifests = relay.history().filter((f) => {
    try { return (JSON.parse(new TextDecoder().decode(f)) as { kind?: string }).kind === 'manifest'; } catch { return false; }
  });
  assert.equal(manifests.length, 1, 'the host broadcast exactly one manifest at start');
  const m = (JSON.parse(new TextDecoder().decode(manifests[0]!)) as { m: GameKeyManifest }).m;
  assert.equal(m.gameId, GID, 'the broadcast manifest is bound to this game id');
});
