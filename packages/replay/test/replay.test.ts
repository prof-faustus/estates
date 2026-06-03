import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { txid, type Tx } from '@estates/tx';
import { initialState, apply, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { type MapContext } from '@estates/chainmap';
import { txForAction, commitOutput, encodeActionCommit } from '@estates/txmap';
import { buildGenesis, MoveChain } from '@estates/ledger';
import { txLeaf, type Envelope } from '@estates/beef';
import { merkleRoot, buildProof, type BlockHeader } from '@estates/spv';
import { replayChain, verifyConfirmedChain, readCommit } from '../src/index.ts';

const pkh = (i: number) => new Uint8Array(createHash('sha256').update(new Uint8Array([i & 0xff, 0x5a])).digest()).slice(0, 20);
const ctx: MapContext = { gameId: new Uint8Array(32).fill(7), genesis: { txid: 'ef'.repeat(32), vout: 0 }, seatPkhs: [pkh(1), pkh(2)], bankPkh: pkh(9) };
const config: EngineConfig = { network: 'regtest', seatCount: 2, bankReserve: 1_000_000 };

/** Play a deterministic game, building the on-chain move chain alongside. */
function playAndChain() {
  let s: GameState = initialState(config);
  let pkhi = 100; const oneUse = () => pkh(pkhi++);
  const g = buildGenesis({ fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 }, cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script, seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }] });
  const chain = new MoveChain(g);
  const moveTxs: Tx[] = [];
  for (let step = 0; step < 400 && s.phase !== 'GAME_OVER' && s.turnIndex < 18; step++) {
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
    chain.append(move);
    moveTxs.push(chain.txs[chain.txs.length - 1]!);
    s = post;
  }
  return { played: s, genesisTxid: g.cursor.txid, moveTxs };
}

test('readCommit extracts the on-chain action commitment from a move tx', () => {
  const { moveTxs } = playAndChain();
  assert.ok(moveTxs.length > 5);
  assert.ok(readCommit(moveTxs[0]!).length > 15, 'commitment blob recovered');
});

test('replayChain reconstructs the EXACT final state from chain data alone (R7)', () => {
  const { played, genesisTxid, moveTxs } = playAndChain();
  const res = replayChain(config, genesisTxid, moveTxs);
  assert.ok(res.ok, res.reason);
  assert.equal(res.movesApplied, moveTxs.length);
  assert.deepEqual(res.finalState, played, 'replayed state == directly-played state');
});

test('a broken link or forged move is rejected', () => {
  const { genesisTxid, moveTxs } = playAndChain();
  // wrong genesis cursor → first move does not link
  assert.equal(replayChain(config, 'ff'.repeat(32), moveTxs).ok, false);
  // drop a middle move → the chain no longer links
  const gapped = [...moveTxs.slice(0, 3), ...moveTxs.slice(4)];
  assert.equal(replayChain(config, genesisTxid, gapped).ok, false);
});

test('verifyConfirmedChain: every move SPV-confirmed AND replays (no node)', () => {
  const { played, genesisTxid, moveTxs } = playAndChain();
  // put each move tx in its own block and build its envelope
  const moves = moveTxs.map((tx, i) => {
    const leaves = [txLeaf(tx), createHash('sha256').update(new Uint8Array([i])).digest()];
    const root = merkleRoot(leaves as Uint8Array[]);
    const header: BlockHeader = { version: 1, prevHash: new Uint8Array(32), merkleRoot: root, time: i + 1, bits: 0x207fffff, nonce: 0 };
    const envelope: Envelope = { tx, proof: buildProof(leaves as Uint8Array[], 0), header };
    return { tx, envelope };
  });
  const res = verifyConfirmedChain(config, genesisTxid, moves);
  assert.ok(res.ok, res.reason);
  assert.deepEqual(res.finalState, played);

  // a forged SPV envelope (wrong root) is rejected
  const bad = moves.map((m, i) => (i === 2 ? { ...m, envelope: { ...m.envelope, header: { ...m.envelope.header, merkleRoot: new Uint8Array(32).fill(9) } } } : m));
  assert.equal(verifyConfirmedChain(config, genesisTxid, bad).ok, false);
});
