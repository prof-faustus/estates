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
  return buildGenesis({
    fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 },
    cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script,
    seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }],
  });
}

test('two peers play a full game over real IP-to-IP sockets and converge byte-for-byte', async () => {
  const aliceId = genIdentity(); const bobId = genIdentity();
  const genesis = makeGenesis();
  let bobPeer: GamePeer | null = null;

  const server = await listen(0, bobId, (link: PeerLink) => { bobPeer = new GamePeer(link, 1, config, ctx, genesis); });
  const port = (server.address() as AddressInfo).port;
  try {
    const clientLink = await connect('127.0.0.1', port, aliceId);
    const alicePeer = new GamePeer(clientLink, 0, config, ctx, genesis);
    await waitFor(() => bobPeer !== null);

    // drive the game: whichever peer's seat is to move takes its turn over the wire
    for (let i = 0; i < 400; i++) {
      if (alicePeer.state.phase === 'GAME_OVER' || alicePeer.state.turnIndex > 16) break;
      if (alicePeer.myTurn()) alicePeer.takeTurn();
      else if (bobPeer!.myTurn()) bobPeer!.takeTurn();
      else { await delay(10); continue; }
      // wait for the move to propagate so both peers are back in lockstep
      await waitFor(() => alicePeer.state.turnIndex === bobPeer!.state.turnIndex && alicePeer.state.current === bobPeer!.state.current);
    }

    // both peers independently reached the SAME state and the SAME on-chain transcript
    assert.deepEqual(alicePeer.state, bobPeer!.state, 'engine state identical on both peers');
    assert.deepEqual(alicePeer.transcript(), bobPeer!.transcript(), 'on-chain transcript identical on both peers');
    assert.ok(alicePeer.transcript().length > 10, `played ${alicePeer.transcript().length - 1} on-chain moves over the socket`);
    // sat conservation across the whole game
    const total = alicePeer.state.seats.reduce((n, s) => n + s.balance, 0) + alicePeer.state.bankReserve;
    assert.equal(total, 1500 + 1500 + 1_000_000, 'no sats minted across the whole on-chain game');

    clientLink.close();
  } finally {
    server.close();
  }
});
