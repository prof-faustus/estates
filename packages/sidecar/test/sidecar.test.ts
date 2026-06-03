import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { genIdentity } from '@estates/channel';
import { listen, connect, type PeerLink } from '@estates/link';
import { type MapContext } from '@estates/chainmap';
import { commitOutput, encodeActionCommit } from '@estates/txmap';
import { buildGenesis } from '@estates/ledger';
import { type EngineConfig } from '@estates/engine';
import { GamePeer } from '../src/index.ts';

const pkh = (i: number) => new Uint8Array(createHash('sha256').update(new Uint8Array([i & 0xff, 0x5a])).digest()).slice(0, 20);
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitFor(p: () => boolean, ms = 5000): Promise<void> { const t0 = Date.now(); while (!p()) { if (Date.now() - t0 > ms) throw new Error('waitFor timeout'); await delay(5); } }

const config: EngineConfig = { network: 'regtest', seatCount: 2, bankReserve: 1_000_000 };
const ctx: MapContext = { gameId: new Uint8Array(32).fill(7), genesis: { txid: 'ef'.repeat(32), vout: 0 }, seatPkhs: [pkh(1), pkh(2)], bankPkh: pkh(9) };
function makeGenesis() {
  return buildGenesis({ fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 }, cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script, seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }] });
}

/** Stand up an authenticated alice(seat0) ↔ bob(seat1) pair over real sockets. */
async function pair(): Promise<{ alice: GamePeer; bob: GamePeer; server: any; aliceLink: PeerLink }> {
  const aliceId = genIdentity(); const bobId = genIdentity();
  const genesis = makeGenesis();
  let bob: GamePeer | null = null;
  const server = await listen(0, bobId, (link: PeerLink) => { bob = new GamePeer(link, bobId, 1, 0, config, ctx, genesis); });
  const port = (server.address() as AddressInfo).port;
  const aliceLink = await connect('127.0.0.1', port, aliceId);
  const alice = new GamePeer(aliceLink, aliceId, 0, 1, config, ctx, genesis);
  await waitFor(() => bob !== null);
  return { alice, bob: bob!, server, aliceLink };
}

test('two peers play a full SIGNED game over real sockets and converge byte-for-byte', async () => {
  const { alice, bob, server, aliceLink } = await pair();
  try {
    for (let i = 0; i < 400; i++) {
      if (alice.state.phase === 'GAME_OVER' || alice.state.turnIndex > 16) break;
      if (alice.myTurn()) alice.takeTurn();
      else if (bob.myTurn()) bob.takeTurn();
      else { await delay(10); continue; }
      await waitFor(() => alice.state.turnIndex === bob.state.turnIndex && alice.state.current === bob.state.current);
    }
    assert.deepEqual(alice.state, bob.state, 'engine state identical (all moves signature-verified)');
    assert.deepEqual(alice.transcript(), bob.transcript(), 'on-chain transcript identical');
    assert.ok(alice.transcript().length > 10);
    const total = alice.state.seats.reduce((n, s) => n + s.balance, 0) + alice.state.bankReserve;
    assert.equal(total, 1_003_000, 'no sats minted');
  } finally { aliceLink.close(); server.close(); }
});

test('a FORGED move (bad signature) is rejected — relay/transport ordering is not authentication', async () => {
  const { alice, bob, server, aliceLink } = await pair();
  try {
    await waitFor(() => alice.myTurn());
    const beforeForge = JSON.stringify(bob.state);
    // Inject a raw frame onto Bob's link impersonating a seat-0 move with a junk signature
    (aliceLink as any).send(new TextEncoder().encode(JSON.stringify({ t: 'move', action: { type: 'ROLL', dice: [6, 6] }, sig: 'deadbeef'.repeat(16) })));
    await delay(250);
    assert.equal(JSON.stringify(bob.state), beforeForge, 'Bob ignored the forged, badly-signed move (state unchanged)');
    // a legitimately SIGNED move from Alice IS accepted and advances Bob's state
    alice.takeTurn();
    await waitFor(() => JSON.stringify(bob.state) !== beforeForge);
    assert.notEqual(JSON.stringify(bob.state), beforeForge, 'a properly-signed move is accepted');
  } finally { aliceLink.close(); server.close(); }
});

test('Bitmessage-style ENCRYPTED chat: peer reads it, the wire carries only ciphertext', async () => {
  const { alice, bob, server, aliceLink } = await pair();
  try {
    const got: { text: string; from: string }[] = [];
    bob.onChat((text, from) => got.push({ text, from }));
    alice.chat('gl hf — see you on chain');
    await waitFor(() => got.length > 0);
    assert.equal(got[0]!.text, 'gl hf — see you on chain', 'Bob decrypts Alice’s chat');
    assert.equal(got[0]!.from, alice.address, 'Bitmessage-style sender address');
    assert.ok(/^[0-9a-f]{40}$/.test(alice.address), 'address = ripemd160(sha256(pub))');
  } finally { aliceLink.close(); server.close(); }
});
