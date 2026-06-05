// A title/card NFT passed from Alice to Bob must DELETE Alice's output: the
// re-mint SPENDS (burns) the prior 1-sat NFT output, so Alice can never use it
// again (the chain enforces it — no copy, no double). This proves that property.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { buildGenesis, buildMove, verifyTrueMove, MoveChain, type Outpoint } from '../src/index.ts';
import type { MoveTx } from '@estates/txmap';

const script = (b: number) => new Uint8Array([0x76, 0xa9, 0x14, b]);
const nftOut = (b: number) => ({ satoshis: 1, script: script(b) });

// A minimal move that re-mints title #3 (and nothing else).
function remintMove(tag: number): MoveTx {
  return { commit: nftOut(0xc0), value: [], nft: [nftOut(tag)], nftTitles: [3], conserved: true, note: 'remint title 3' };
}

function genesis() {
  return buildGenesis({ fundingOutpoint: { txid: 'ab'.repeat(32), vout: 0 }, cursorScript: script(0x01), seatFunds: [{ satoshis: 1500, script: script(0x02) }] });
}

test('a re-mint SPENDS the prior NFT outpoint as an input (Alice’s output is consumed)', () => {
  const alicesNft: Outpoint = { txid: 'aa'.repeat(32), vout: 7 };
  const prior = new Map([[3, alicesNft]]);
  const { tx, nftOutpoints } = buildMove(genesis().cursor, remintMove(0xb0), 0xffffffff, 0, prior);
  // the tx spends Alice's NFT output
  assert.ok(tx.inputs.some((i) => i.prevTxid === alicesNft.txid && i.prevVout === alicesNft.vout), 'Alice’s NFT output is an input (burned)');
  // and mints Bob's new one, which becomes title 3's new outpoint
  const bobsNft = nftOutpoints.get(3)!;
  assert.equal(bobsNft.vout, 1, 'new NFT output (vout 1 = after commit, no value legs)');
  assert.notEqual(`${bobsNft.txid}:${bobsNft.vout}`, `${alicesNft.txid}:${alicesNft.vout}`, 'a fresh output, not the old one');
});

test('verifyTrueMove REJECTS a re-mint that fails to burn the prior output (a copy)', () => {
  const alicesNft: Outpoint = { txid: 'aa'.repeat(32), vout: 7 };
  const prior = new Map([[3, alicesNft]]);
  // build WITHOUT the prior map → the move does not spend Alice's output
  const copy = buildMove(genesis().cursor, remintMove(0xb0)); // no priorNftOutpoints
  assert.equal(verifyTrueMove(copy.tx, prior, [3]).ok, false, 'a re-mint that does not spend the prior NFT is rejected as a copy');
  // build WITH the prior map → it burns Alice's output → accepted
  const move = buildMove(genesis().cursor, remintMove(0xb0), 0xffffffff, 0, prior);
  assert.ok(verifyTrueMove(move.tx, prior, [3]).ok, 'the true move is accepted');
});

test('MoveChain tracks custody: each transfer burns the CURRENT output and the next burns the one after', () => {
  const chain = new MoveChain(genesis(), new Map([[3, { txid: 'aa'.repeat(32), vout: 7 }]]));
  const first = chain.nftOutpoint(3)!;                 // Alice's genesis NFT
  chain.append(remintMove(0xb0));                       // Alice -> Bob
  const second = chain.nftOutpoint(3)!;                 // Bob's NFT
  assert.notDeepEqual(second, first, 'title 3 now points at Bob’s fresh output');
  // the move that produced Bob's output must have spent Alice's
  const aliceToBob = chain.txs[chain.txs.length - 1]!;
  assert.ok(aliceToBob.inputs.some((i) => i.prevTxid === first.txid && i.prevVout === first.vout), 'Alice’s output burned');

  chain.append(remintMove(0xc1));                       // Bob -> Carol
  const third = chain.nftOutpoint(3)!;
  const bobToCarol = chain.txs[chain.txs.length - 1]!;
  assert.ok(bobToCarol.inputs.some((i) => i.prevTxid === second.txid && i.prevVout === second.vout), 'Bob’s output burned in the next transfer');
  assert.notDeepEqual(third, second);
});

test('the FIRST mint of a title (no prior outpoint) is allowed without a burn', () => {
  const { tx } = buildMove(genesis().cursor, remintMove(0xb0), 0xffffffff, 0, new Map()); // no prior for title 3
  assert.ok(verifyTrueMove(tx, new Map(), [3]).ok, 'first mint has nothing to burn');
});
