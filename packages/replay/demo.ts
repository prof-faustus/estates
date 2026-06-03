/**
 * Runnable end-to-end demo of the ON-CHAIN architecture (headless).
 *
 *   pnpm --filter @estates/replay run demo
 *
 * Plays a full deterministic 2-seat game where EVERY move becomes a real BSV
 * transaction (commitment + value legs), linked into the on-chain move chain,
 * each wrapped in an SPV envelope. Then reconstructs and verifies the entire game
 * from the chain alone — proving the stack end to end with no node, no REST, no
 * trust. (Real broadcast + real Merkle proofs from your node are the sidecar's
 * job; the block here is synthesised so the demo runs anywhere.)
 */
import { createHash } from 'node:crypto';
import { txid, type Tx } from '@estates/tx';
import { initialState, apply, type GameState, type Action, type EngineConfig } from '@estates/engine';
import { type MapContext } from '@estates/chainmap';
import { txForAction, commitOutput, encodeActionCommit, decodeActionCommit } from '@estates/txmap';
import { buildGenesis, MoveChain } from '@estates/ledger';
import { txLeaf, type Envelope } from '@estates/beef';
import { merkleRoot, buildProof, type BlockHeader } from '@estates/spv';
import { verifyConfirmedChain, readCommit } from './src/index.ts';

const pkh = (i: number) => new Uint8Array(createHash('sha256').update(new Uint8Array([i & 0xff, 0x5a])).digest()).slice(0, 20);
const ctx: MapContext = { gameId: new Uint8Array(32).fill(7), genesis: { txid: 'ef'.repeat(32), vout: 0 }, seatPkhs: [pkh(1), pkh(2)], bankPkh: pkh(9) };
const config: EngineConfig = { network: 'regtest', seatCount: 2, bankReserve: 1_000_000 };

let s: GameState = initialState(config);
let pkhi = 100; const oneUse = () => pkh(pkhi++);
const g = buildGenesis({
  fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 },
  cursorScript: commitOutput(encodeActionCommit({ type: 'END_TURN' }, 0, 0), pkh(9)).script,
  seatFunds: [{ satoshis: 1500, script: pkh(1) }, { satoshis: 1500, script: pkh(2) }],
});
const chain = new MoveChain(g);
const moves: { tx: Tx; envelope: Envelope }[] = [];

console.log(`# ESTATES on-chain game — genesis tx ${g.cursor.txid.slice(0, 16)}…  (2 seats, regtest)`);
for (let step = 0; step < 600 && s.phase !== 'GAME_OVER' && s.turnIndex < 12; step++) {
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
  const tx = chain.txs[chain.txs.length - 1]!;
  const leaves = [txLeaf(tx), createHash('sha256').update(new Uint8Array([step])).digest()] as Uint8Array[];
  const header: BlockHeader = { version: 1, prevHash: new Uint8Array(32), merkleRoot: merkleRoot(leaves), time: step + 1, bits: 0x207fffff, nonce: 0 };
  moves.push({ tx, envelope: { tx, proof: buildProof(leaves, 0), header } });

  const dec = decodeActionCommit(readCommit(tx));
  const legs = move.value.length + move.nft.length;
  console.log(`  move ${String(moves.length).padStart(2)}  tx ${txid(tx).slice(0, 16)}…  seat ${seat}  ${dec.action.type.padEnd(8)}  ${legs} on-chain leg(s)  conserved=${move.conserved}`);
  s = post;
}

console.log(`# played ${moves.length} on-chain moves; verifying the whole game from chain data alone…`);
const res = verifyConfirmedChain(config, g.cursor.txid, moves);
if (!res.ok) { console.error(`✗ VERIFY FAILED: ${res.reason}`); process.exit(1); }
console.log(`✓ VERIFIED: every move SPV-confirmed (no node) and replayed; ${res.movesApplied} moves → final state`);
console.log(`  final balances: ${res.finalState!.seats.map((x) => `seat${x.id}=${x.balance}`).join('  ')}  reserve=${res.finalState!.bankReserve}`);
console.log(`  transcript = ${chain.transcript().length} txids (genesis + ${moves.length} moves), all on chain, all auditable.`);
process.exit(0);
