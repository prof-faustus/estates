import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { txid } from '@estates/tx';
import { initialState, apply, type GameState, type Action } from '@estates/engine';
import { type MapContext } from '@estates/chainmap';
import { txForAction, commitOutput, encodeActionCommit, decodeActionCommit } from '@estates/txmap';
import { buildGenesis, buildMove, MoveChain } from '../src/index.ts';

const pkh = (i: number) => new Uint8Array(createHash('sha256').update(new Uint8Array([i & 0xff, 0x5a])).digest()).slice(0, 20);
const ctx: MapContext = {
  gameId: new Uint8Array(32).fill(7), genesis: { txid: 'ef'.repeat(32), vout: 0 },
  seatPkhs: [pkh(1), pkh(2)], bankPkh: pkh(9),
};
const funding = { txid: 'ab'.repeat(32), vout: 0 };

function genesis() {
  return buildGenesis({
    fundingOutpoint: funding,
    cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script,
    seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }],
    mints: [{ satoshis: 1, script: pkh(3) }, { satoshis: 1, script: pkh(4) }], // deck NFTs
  });
}

test('genesis is a real tx with a real txid; output 0 is the move-chain cursor', () => {
  const g = genesis();
  assert.equal(g.cursor.txid, txid(g.tx));
  assert.equal(g.cursor.vout, 0);
  assert.equal(g.tx.outputs[0]!.value, 1n === 1n ? 1 : 1, '1-sat cursor');
  assert.equal(g.tx.outputs.length, 1 + 2 + 2, 'cursor + 2 seats + 2 deck NFTs');
  assert.equal(g.tx.inputs[0]!.prevTxid, funding.txid, 'spends the funding UTXO');
});

test('every move is a real tx that LINKS to the previous (chain of txids)', () => {
  let s: GameState = initialState({ network: 'regtest', seatCount: 2, bankReserve: 1_000_000 });
  let pkhi = 100;
  const oneUse = () => pkh(pkhi++);
  const chain = new MoveChain(genesis());
  let prevId = chain.cursor.txid;
  let moves = 0;
  const seenTxids = new Set<string>([prevId]);

  for (let step = 0; step < 400 && s.phase !== 'GAME_OVER' && s.turnIndex < 20; step++) {
    const seat = s.current;
    let action: Action;
    switch (s.phase) {
      case 'AWAIT_ROLL': action = { type: 'ROLL', dice: [1 + (step % 6), 1 + ((step * 5) % 6)] as const }; break;
      case 'AWAIT_BUY': action = s.seats[seat]!.balance > 600 ? { type: 'BUY' } : { type: 'DECLINE' }; break;
      case 'AWAIT_TAX': action = { type: 'PAY_TAX', choice: 'flat' }; break;
      default: action = { type: 'END_TURN' };
    }
    const r = apply(s, action); if (!r.ok) { const r2 = apply(s, { type: 'END_TURN' }); if (!r2.ok) break; s = r2.state; continue; }
    const post = r.state;
    const move = txForAction(s, post, action, post.turnIndex, seat, ctx, oneUse);
    const built = buildMove(chain.cursor, move);

    // links to the previous tx
    assert.equal(built.tx.inputs[0]!.prevTxid, prevId, 'move spends the prior cursor');
    // the on-chain commitment decodes back to this exact move
    const decoded = decodeActionCommit(move.commit.script.slice(1, 1 + encodeActionCommit(action, post.turnIndex, seat).length));
    assert.deepEqual(decoded.action, action, 'commitment is the move');

    const id = chain.append(move);
    assert.equal(seenTxids.has(id), false, 'every move has a unique real txid');
    seenTxids.add(id);
    prevId = id;
    s = post; moves++;
  }

  assert.ok(moves >= 15, `built a chain of ${moves} on-chain moves`);
  const transcript = chain.transcript();
  assert.equal(transcript.length, moves + 1, 'transcript = genesis + every move');
  assert.equal(new Set(transcript).size, transcript.length, 'all txids distinct');
});
