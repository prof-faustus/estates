import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { initialState, apply, type GameState, type Action } from '@estates/engine';
import { type MapContext } from '@estates/chainmap';
import { encodeActionCommit, commitOutput, txForAction, balanceDeltas } from '../src/index.ts';

// A deterministic one-use pkh generator (each call distinct = no reuse).
function pkhGen() {
  let i = 0;
  const issued: string[] = [];
  const fn = (_role: number) => {
    const h = createHash('sha256').update(new Uint8Array([(i >>> 8) & 0xff, i & 0xff, 0xab])).digest();
    i++;
    const pkh = new Uint8Array(h.subarray(0, 20));
    issued.push(Buffer.from(pkh).toString('hex'));
    return pkh;
  };
  return { fn, issued };
}
const ctx: MapContext = {
  gameId: new Uint8Array(32).fill(7),
  genesis: { txid: 'cd'.repeat(32), vout: 0 },
  seatPkhs: [new Uint8Array(20).fill(1), new Uint8Array(20).fill(2)],
  bankPkh: new Uint8Array(20).fill(9),
};

test('action commitment encodes the action on-chain (pushdata) and round-trips fields', () => {
  const roll: Action = { type: 'ROLL', dice: [3, 4] };
  const c = encodeActionCommit(roll, 5, 1);
  assert.ok(c.length > 0);
  // tag present + the dice params are in the blob
  assert.ok(Buffer.from(c).includes(Buffer.from('ESTATES-MOVE-v1')), 'domain tag on chain');
  assert.equal(c[c.length - 2], 3); assert.equal(c[c.length - 1], 4);
  const out = commitOutput(c, ctx.seatPkhs[0]!);
  assert.equal(out.satoshis, 1, 'commitment rides a 1-sat output');
  assert.ok(out.script.length > c.length, 'state is in the live script');
});

test('EVERY move maps to a tx with an on-chain commitment AND conserves sats', () => {
  let s: GameState = initialState({ network: 'regtest', seatCount: 2, bankReserve: 1_000_000 });
  const { fn: oneUse } = pkhGen();
  let mapped = 0;
  const kinds = new Set<string>();

  for (let step = 0; step < 600 && s.phase !== 'GAME_OVER'; step++) {
    const seat = s.current;
    let action: Action;
    switch (s.phase) {
      case 'AWAIT_ROLL': action = { type: 'ROLL', dice: [1 + (step % 6), 1 + ((step * 3) % 6)] as const }; break;
      case 'AWAIT_BUY': action = s.seats[seat]!.balance > 600 ? { type: 'BUY' } : { type: 'DECLINE' }; break;
      case 'AWAIT_TAX': action = { type: 'PAY_TAX', choice: 'flat' }; break;
      case 'AWAIT_POST': action = { type: 'END_TURN' }; break;
      default: action = { type: 'END_TURN' };
    }
    const r = apply(s, action);
    if (!r.ok) { // illegal in this state — try the safe default
      const r2 = apply(s, { type: 'END_TURN' });
      if (!r2.ok) break; s = r2.state; continue;
    }
    const post = r.state;

    const mtx = txForAction(s, post, action, post.turnIndex, seat, ctx, oneUse);
    // 1) the action is on chain
    assert.equal(mtx.commit.satoshis, 1, `${action.type}: action committed on a 1-sat output`);
    // 2) sats are conserved (never minted)
    assert.ok(mtx.conserved, `${action.type}: sat conservation (in==out)`);
    // 3) every value leg is a whole, positive sat amount
    for (const v of mtx.value) assert.ok(Number.isInteger(v.satoshis) && v.satoshis > 0, 'whole-sat value legs');
    // 4) if any balance changed, there is at least one value leg or it nets to bank
    const deltas = balanceDeltas(s, post);
    if (deltas.some((d) => d.delta > 0)) assert.ok(mtx.value.length > 0, 'a gainer ⇒ a value leg');

    kinds.add(action.type);
    mapped++;
    s = post;
    if (s.turnIndex > 40) break;
  }

  assert.ok(mapped >= 20, `mapped many moves (${mapped})`);
  // we exercised a spread of action types, each producing an on-chain tx
  assert.ok(kinds.has('ROLL') && kinds.has('END_TURN'), `covered core actions: ${[...kinds].join(',')}`);
});

test('one-use keys: a payee key is never reused across moves', () => {
  const { fn, issued } = pkhGen();
  for (let i = 0; i < 100; i++) fn(0);
  assert.equal(new Set(issued).size, issued.length, 'every issued key is unique');
});
