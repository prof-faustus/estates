import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { genIdentity, signData, type Identity } from '@estates/channel';
import { listen, connect, type PeerLink } from '@estates/link';
import { type MapContext } from '@estates/chainmap';
import { commitOutput, encodeActionCommit } from '@estates/txmap';
import { buildGenesis } from '@estates/ledger';
import { initialState, apply, type EngineConfig } from '@estates/engine';
import { commit as beaconCommit, roll as beaconRoll, ZERO_BEACON } from '@estates/beacon';
import { GamePeer, decodeFrame, isAction } from '../src/index.ts';

const pkh = (i: number) => new Uint8Array(createHash('sha256').update(new Uint8Array([i & 0xff, 0x5a])).digest()).slice(0, 20);
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(p: () => boolean, ms = 6000): Promise<void> { const t0 = Date.now(); while (!p()) { if (Date.now() - t0 > ms) throw new Error('waitFor timeout'); await delay(5); } }

const config: EngineConfig = { network: 'regtest', seatCount: 2, bankReserve: 1_000_000 };
const ctx: MapContext = { gameId: new Uint8Array(32).fill(7), genesis: { txid: 'ef'.repeat(32), vout: 0 }, seatPkhs: [pkh(1), pkh(2)], bankPkh: pkh(9) };
function makeGenesis() {
  return buildGenesis({ fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 }, cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script, seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }] });
}
async function pair(): Promise<{ alice: GamePeer; bob: GamePeer; aliceId: Identity; server: any; aliceLink: PeerLink }> {
  const aliceId = genIdentity(); const bobId = genIdentity();
  const genesis = makeGenesis();
  let bob: GamePeer | null = null;
  const server = await listen(0, bobId, (link: PeerLink) => { bob = new GamePeer(link, bobId, 1, 0, config, ctx, genesis); });
  const port = (server.address() as AddressInfo).port;
  const aliceLink = await connect('127.0.0.1', port, aliceId);
  const alice = new GamePeer(aliceLink, aliceId, 0, 1, config, ctx, genesis);
  await waitFor(() => bob !== null);
  return { alice, bob: bob!, aliceId, server, aliceLink };
}

test('a full BEACON-diced game over real sockets converges byte-for-byte', async () => {
  const { alice, bob, server, aliceLink } = await pair();
  try {
    for (let i = 0; i < 300; i++) {
      if (alice.state.phase === 'GAME_OVER' || alice.state.turnIndex > 12) break;
      const before = JSON.stringify(alice.state);
      if (alice.myTurn()) alice.takeTurn();
      else if (bob.myTurn()) bob.takeTurn();
      else { await delay(10); continue; }
      // wait for the move (incl. the commit→reveal beacon round) to fully settle
      await waitFor(() => JSON.stringify(alice.state) === JSON.stringify(bob.state) && JSON.stringify(alice.state) !== before);
    }
    assert.deepEqual(alice.state, bob.state, 'state identical (beacon dice + signed moves)');
    assert.deepEqual(alice.transcript(), bob.transcript(), 'on-chain transcript identical');
    assert.ok(alice.transcript().length > 8);
    const total = alice.state.seats.reduce((n, s) => n + s.balance, 0) + alice.state.bankReserve;
    assert.equal(total, 1_003_000, 'no sats minted');
  } finally { aliceLink.close(); server.close(); }
});

test('a signed ROLL with MOVER-CHOSEN dice (not the beacon) is REJECTED (#2)', async () => {
  const { bob, aliceId, server, aliceLink } = await pair();
  try {
    const before = JSON.stringify(bob.state);
    // Craft a ROLL that is correctly SIGNED by Alice (seat 0, the active seat) and
    // carries a self-consistent commit/reveal transcript — but whose dice are
    // CHOSEN, not the beacon of the revealed secrets.
    const sm = new Uint8Array(randomBytes(32)); const sp = new Uint8Array(randomBytes(32));
    const cm = beaconCommit(sm); const cp = beaconCommit(sp);
    const actual = beaconRoll([{ seat: 0, secret: sm }, { seat: 1, secret: sp }], initialState(config).turnIndex, ZERO_BEACON).dice;
    const chosen: [number, number] = actual[0] === 1 ? [6, 6] : [1, 1]; // guaranteed ≠ the beacon
    const action = { type: 'ROLL', dice: chosen };
    const post = apply(initialState(config), action as any);
    assert.ok(post.ok);
    const payload = new TextEncoder().encode(JSON.stringify({ k: 'estates-move-v1', g: hex(ctx.gameId), turnIndex: post.state.turnIndex, actor: 0, action }));
    const sig = signData(payload, aliceId.signPriv);
    const frame = { t: 'move', action, sig: hex(sig), beacon: { cm: hex(cm), cp: hex(cp), sm: hex(sm), sp: hex(sp), seatM: 0, seatP: 1 } };
    (aliceLink as any).send(new TextEncoder().encode(JSON.stringify(frame)));
    await delay(250);
    assert.equal(JSON.stringify(bob.state), before, 'Bob rejected the chosen-dice ROLL (dice ≠ beacon)');
  } finally { aliceLink.close(); server.close(); }
});

test('a badly-SIGNED move is rejected', async () => {
  const { bob, server, aliceLink } = await pair();
  try {
    const before = JSON.stringify(bob.state);
    (aliceLink as any).send(new TextEncoder().encode(JSON.stringify({ t: 'move', action: { type: 'END_TURN' }, sig: 'deadbeef'.repeat(16) })));
    await delay(200);
    assert.equal(JSON.stringify(bob.state), before, 'forged-signature move ignored');
  } finally { aliceLink.close(); server.close(); }
});

test('the signed payload BINDS the output-key manifest — a tampered pkhs is rejected (#3)', async () => {
  const { bob, aliceId, server, aliceLink } = await pair();
  try {
    const before = JSON.stringify(bob.state);
    const action = { type: 'FORFEIT' };                 // a non-roll move legal for the active seat
    const post = apply(initialState(config), action as any);
    assert.ok(post.ok);
    // Alice signs a payload that commits to pkhs {0: aa…} (matching movePayload's shape + order)
    const signedPkhs = { 0: 'aa'.repeat(20) };
    const payload = new TextEncoder().encode(JSON.stringify({ k: 'estates-move-v1', g: hex(ctx.gameId), turnIndex: post.state.turnIndex, actor: 0, action, pkhs: signedPkhs, beacon: null }));
    const sig = signData(payload, aliceId.signPriv);
    // …but the frame on the wire carries a DIFFERENT manifest {0: bb…} (output-key swap)
    const frame = { t: 'move', action, sig: hex(sig), pkhs: { 0: 'bb'.repeat(20) } };
    (aliceLink as any).send(new TextEncoder().encode(JSON.stringify(frame)));
    await delay(250);
    assert.equal(JSON.stringify(bob.state), before, 'a move whose pkhs differ from the signed manifest is rejected');
  } finally { aliceLink.close(); server.close(); }
});

test('Bitmessage-style ENCRYPTED chat decrypts with the right address', async () => {
  const { alice, bob, server, aliceLink } = await pair();
  try {
    const got: { text: string; from: string }[] = [];
    bob.onChat((text, from) => got.push({ text, from }));
    alice.chat('gl hf — beacon dice, signed moves, on chain');
    await waitFor(() => got.length > 0);
    assert.equal(got[0]!.text, 'gl hf — beacon dice, signed moves, on chain');
    assert.equal(got[0]!.from, alice.address);
    assert.ok(/^[0-9a-f]{40}$/.test(alice.address));
  } finally { aliceLink.close(); server.close(); }
});

// ---- the seat identity IS the player's own non-custodial key (no throwaway) ---
test('moves are signed by the PLAYER key, and chat is addressed by it', async () => {
  const { genMaster } = await import('@estates/keys');
  const { identityFrom, signingKeyFromMaster } = await import('@estates/channel');
  const { addressOf } = await import('@estates/chat');
  const kA = genMaster(); const kB = genMaster();                 // players' non-custodial keys
  const idA = identityFrom(kA.priv); const idB = identityFrom(kB.priv);
  const genesis = makeGenesis();
  let bob: GamePeer | null = null;
  const server = await listen(0, idB, (link: PeerLink) => { bob = new GamePeer(link, idB, 1, 0, config, ctx, genesis); });
  const port = (server.address() as AddressInfo).port;
  const aliceLink = await connect('127.0.0.1', port, idA);
  const alice = new GamePeer(aliceLink, idA, 0, 1, config, ctx, genesis);
  await waitFor(() => bob !== null);
  try {
    // Bitmessage address = the player's own key (ripemd160(sha256(pub)))
    assert.equal(alice.address, addressOf(kA.pub), 'Alice’s address is her player key');
    assert.equal(bob!.address, addressOf(kB.pub), 'Bob’s address is his player key');
    // over the authenticated channel each peer learned the OTHER player's real key
    assert.equal(hex(aliceLink.peerIdPub), hex(kB.pub), 'Alice’s link peer = Bob’s master (wallet) key');
    // the SIGNING key is the Ed25519 key DERIVED from the same master (not a throwaway)
    assert.equal(hex(aliceLink.peerSignPub), hex(signingKeyFromMaster(kB.priv).pub), 'Bob’s signing key is derived from his master');
    // a real move from Alice is accepted (it is signed by her player key, which Bob registered for seat 0)
    const before = JSON.stringify(bob!.state);
    await waitFor(() => alice.myTurn());
    alice.takeTurn();
    await waitFor(() => JSON.stringify(bob!.state) !== before);
    assert.notEqual(JSON.stringify(bob!.state), before, 'Bob applied Alice’s player-key-signed move');
  } finally { aliceLink.close(); server.close(); }
});

// ---- FRAME DECODER: fail-closed + fuzz-proof (one hostile socket peer) ---------
// Security claim: a hostile peer cannot crash recv, drive the engine with an
// arbitrary action, or DoS via a malformed/oversized frame. A signature proves
// authorship, NOT well-formedness — decodeFrame proves the latter, before anything.
const frame = (o: unknown): Uint8Array => new TextEncoder().encode(JSON.stringify(o));
const H32 = 'aa'.repeat(32);   // 32-byte hex (commitment/secret)
const HSIG = 'cc'.repeat(64);  // 64-byte hex (Ed25519 sig)

test('decodeFrame accepts well-formed bc/br/move/chat and rejects hostile shapes', () => {
  // valid
  assert.ok(decodeFrame(frame({ t: 'bc', turn: 0, c: H32 })));
  assert.ok(decodeFrame(frame({ t: 'br', turn: 3, s: H32 })));
  assert.ok(decodeFrame(frame({ t: 'move', action: { type: 'END_TURN' }, sig: HSIG })));
  const mv = decodeFrame(frame({ t: 'move', action: { type: 'ROLL', dice: [2, 5] }, sig: HSIG, beacon: { cm: H32, cp: H32, sm: H32, sp: H32, seatM: 1, seatP: 0 }, pkhs: { '0:commit': 'bb'.repeat(20) } }));
  assert.ok(mv && mv.t === 'move' && mv.beacon && Object.keys(mv.pkhs).length === 1);
  // hostile — every one must be rejected (null)
  for (const bad of [
    new Uint8Array([0xff, 0xfe]), frame('not-an-object'), frame(null), frame([]), frame(42),
    frame({ t: 'nope' }),
    frame({ t: 'bc', turn: -1, c: H32 }), frame({ t: 'bc', turn: 1e12, c: H32 }), frame({ t: 'bc', turn: 0, c: 'zz' }),
    frame({ t: 'move', action: { type: 'EVIL' }, sig: HSIG }),            // arbitrary action → the old apply() crash
    frame({ t: 'move', action: { type: 'ROLL', dice: [9, 9] }, sig: HSIG }), // out-of-range dice
    frame({ t: 'move', action: { type: 'BUY' }, sig: 'short' }),          // bad sig length
    frame({ t: 'move', action: { type: 'BUY' }, sig: HSIG, beacon: { cm: 'x' } }), // malformed beacon present
    frame({ t: 'move', action: { type: 'BUY' }, sig: HSIG, pkhs: { k: 'nothex' } }), // bad pkh
    frame({ t: 'move', action: { type: 'BUY' }, sig: HSIG, pkhs: Object.fromEntries(Array.from({ length: 999 }, (_, i) => [String(i), 'bb'.repeat(20)])) }), // oversized manifest
    frame({ t: 'chat', env: {} }), frame({ t: 'chat', env: { recipients: 'x' } }),
  ]) assert.equal(decodeFrame(bad), null, `rejected: ${(JSON.stringify(bad) ?? '').slice(0, 0)}hostile`);
});

test('a HOSTILE move frame never crashes a live peer / never advances state', async () => {
  const { bob, aliceLink, server } = await pair();
  try {
    const before = JSON.stringify(bob.state);
    const hostile = [
      new Uint8Array([1, 2, 3]), frame('x'), frame({ t: 'move', action: { type: '__proto__' }, sig: HSIG }),
      frame({ t: 'move', action: { type: 'ROLL', dice: ['a', 'b'] }, sig: HSIG }),
      frame({ t: 'bc', turn: 1e15, c: 'zz' }), frame({ t: 'chat', env: { recipients: [null] } }),
    ];
    for (const h of hostile) (aliceLink as any).send(h);
    await delay(200);
    assert.equal(JSON.stringify(bob.state), before, 'no hostile frame advanced or corrupted state');
  } finally { aliceLink.close(); server.close(); }
});

test('decodeFrame is FUZZ-PROOF: 100k random frames never throw or hang', () => {
  let rng = 0x1234abcd >>> 0; const rand = () => { rng = (rng * 1103515245 + 12345) >>> 0; return rng; };
  const t0 = Date.now();
  for (let i = 0; i < 100_000; i++) {
    const len = rand() % 256;
    const b = new Uint8Array(len);
    for (let k = 0; k < len; k++) b[k] = rand() & 0xff;
    let out: unknown = 'unset';
    assert.doesNotThrow(() => { out = decodeFrame(b); });
    assert.ok(out === null || typeof out === 'object');
  }
  assert.ok(Date.now() - t0 < 8000, 'bounded work — no hang');
  // sanity: the action validator rejects a classic prototype-pollution attempt
  assert.equal(isAction({ type: '__proto__' }), false);
});
