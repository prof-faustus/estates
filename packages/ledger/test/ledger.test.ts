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

// ---- #2: genesis key manifest — every output is a fresh derived/covenant key ----
test('verifyGenesisManifest: accepts a fully-derived+certified genesis, rejects raw/reused/forged', async () => {
  const { genMaster } = await import('@estates/keys');
  const { covenantOutput, rulesHash } = await import('@estates/bank');
  const { paymentOutput } = await import('@estates/onchain');
  const { buildGenesis, certifyGenesisKey, covenantGenesisEntry, verifyGenesisManifest } = await import('../src/index.ts');

  const gameId = 'a1'.repeat(32);
  const gid = fromHexLocal(gameId);                            // 32-byte game id (covenant binding)
  const A = genMaster(); const B = genMaster();
  // genesis: out0 cursor (A), out1 seat-fund A, out2 seat-fund B, out3 covenant reserve
  const e0 = certifyGenesisKey(A, gameId, 'regtest', 'cursor', 0);
  const e1 = certifyGenesisKey(A, gameId, 'regtest', 'seat-fund', 1);
  const e2 = certifyGenesisKey(B, gameId, 'regtest', 'seat-fund', 2);
  const e3 = covenantGenesisEntry(3, 'reserve', rulesHash(gid));
  const g = buildGenesis({
    fundingOutpoint: { txid: 'cd'.repeat(32), vout: 0 },
    cursorScript: paymentOutput(1, fromHexLocal(e0.pkh!)).script,
    seatFunds: [{ satoshis: 1500, script: paymentOutput(1500, fromHexLocal(e1.pkh!)).script }, { satoshis: 1500, script: paymentOutput(1500, fromHexLocal(e2.pkh!)).script }],
    mints: [{ satoshis: 1_000_000, script: covenantOutput(1_000_000, rulesHash(gid)).script }],
  });
  const manifest = [e0, e1, e2, e3];
  assert.ok(verifyGenesisManifest(g.tx, manifest, gameId).ok, 'a fully-derived + covenant genesis verifies');

  // a RAW output with no entry → rejected
  assert.equal(verifyGenesisManifest(g.tx, [e0, e1, e2], gameId).ok, false, 'missing entry for an output is rejected');
  // a TAMPERED pkh (cert no longer matches) → rejected
  const forged = { ...e1, pkh: e2.pkh! };
  assert.equal(verifyGenesisManifest(g.tx, [e0, forged, e2, e3], gameId).ok, false, 'pkh ≠ hash160(derivedSpendPub) rejected');
  // REUSED key across two outputs → rejected
  const reuse = certifyGenesisKey(A, gameId, 'regtest', 'cursor', 0); // same key as e0
  const dupTx = buildGenesis({ fundingOutpoint: { txid: 'cd'.repeat(32), vout: 0 }, cursorScript: paymentOutput(1, fromHexLocal(e0.pkh!)).script, seatFunds: [{ satoshis: 1500, script: paymentOutput(1500, fromHexLocal(e0.pkh!)).script }] });
  assert.equal(verifyGenesisManifest(dupTx.tx, [e0, { ...reuse, outputIndex: 1, purpose: 'seat-fund' }], gameId).ok, false, 'a one-use key reused across outputs is rejected');
});

function fromHexLocal(h: string): Uint8Array { const b = new Uint8Array(h.length / 2); for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16); return b; }
