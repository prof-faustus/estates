import { test } from 'node:test';
import assert from 'node:assert/strict';
import { initialState, apply, type GameState } from '@estates/engine';
import { decodeTitleState } from '@estates/onchain';
import { titleToNftState, titleToNftOutput, nftReflectsEngine, emitForAction, type MapContext } from '../src/index.ts';

const ctx: MapContext = {
  gameId: new Uint8Array(32).fill(5),
  genesis: { txid: 'ab'.repeat(32), vout: 0 },
  seatPkhs: [new Uint8Array(20).fill(1), new Uint8Array(20).fill(2)],
  bankPkh: new Uint8Array(20).fill(9),
};
const cfg = { network: 'regtest' as const, seatCount: 2, bankReserve: 1_000_000 };

function setOwner(s: GameState, ids: number[], owner: number): GameState {
  const titles = { ...s.titles };
  for (const id of ids) titles[id] = { ...titles[id]!, owner };
  return { ...s, titles };
}

test('an unowned title maps to a 1-sat NFT held by the bank', () => {
  const s = initialState(cfg);
  const out = titleToNftOutput(s, 3, ctx);
  assert.equal(out.satoshis, 1);
  assert.equal(decodeTitleState(extractBlob(out.script)).propertyId, 3);
});

test('engine title state round-trips through the NFT blob (build + mortgage reflected)', () => {
  let s = { ...setOwner(initialState(cfg), [3], 0) };
  s = { ...s, titles: { ...s.titles, 3: { owner: 0, buildLevel: 3, mortgaged: false } } };
  assert.equal(nftReflectsEngine(s, 3, ctx), true);
  const st = titleToNftState(s, 3, ctx);
  assert.equal(st.buildLevel, 3);
  assert.equal(st.mortgaged, false);
  // flip mortgaged
  s = { ...s, titles: { ...s.titles, 3: { owner: 0, buildLevel: 0, mortgaged: true } } };
  assert.equal(titleToNftState(s, 3, ctx).mortgaged, true);
});

test('a buy emits NFT(bank→buyer) + price(→reserve)', () => {
  // drive a real buy: roll to Cinder Alley (3), buy
  let s = initialState(cfg);
  s = step(s, { type: 'ROLL', dice: [1, 2] });
  s = step(s, { type: 'BUY' });
  const tx = emitForAction(s, 3, 'buy', ctx);
  assert.equal(tx.outputs[0]!.satoshis, 1);             // the NFT now owned by buyer
  assert.equal(tx.outputs[1]!.satoshis, 60);            // price to the reserve
  assert.equal(decodeTitleState(extractBlob(tx.outputs[0]!.script)).propertyId, 3);
});

test('a build re-mints the NFT at the new level + pays the build cost', () => {
  let s: GameState = { ...setOwner(initialState(cfg), [6, 8, 9], 0), phase: 'AWAIT_POST' }; // full Sky
  s = step(s, { type: 'BUILD', propertyId: 6 });
  const tx = emitForAction(s, 6, 'build', ctx);
  assert.equal(decodeTitleState(extractBlob(tx.outputs[0]!.script)).buildLevel, 1);
  assert.equal(tx.outputs[1]!.satoshis, 50); // Sky build cost
});

test('a mortgage re-mints with the flag set + pays the mortgage value to the owner', () => {
  let s: GameState = { ...setOwner(initialState(cfg), [1, 3], 0), phase: 'AWAIT_POST' };
  s = step(s, { type: 'MORTGAGE', propertyId: 1 });
  const tx = emitForAction(s, 1, 'mortgage', ctx);
  assert.equal(decodeTitleState(extractBlob(tx.outputs[0]!.script)).mortgaged, true);
  assert.equal(tx.outputs[1]!.satoshis, 30); // mortgage value of base 60
});

// helpers
function step(s: GameState, a: Parameters<typeof apply>[1]): GameState {
  const r = apply(s, a); assert.ok(r.ok, r.ok ? '' : r.code); return r.state;
}
/** Pull the leading pushdata (the 73-byte state blob) out of an NFT locking script. */
function extractBlob(script: Uint8Array): Uint8Array {
  // script begins with a pushdata op for the 73-byte blob: 0x4c <len> <blob...>
  if (script[0] === 0x4c) return script.slice(2, 2 + script[1]!);
  return script.slice(1, 1 + script[0]!); // direct push
}

// ---- audit #9: semantic NFT validation (groupId tied to propertyId) ----------
import { validateTitleSemantics } from '../src/index.ts';
import { loadParams } from '@estates/params';
test('validateTitleSemantics: every genesis title is semantically valid; mismatches rejected', () => {
  const s = initialState(cfg);
  const P = loadParams();
  // every titled space the engine maps must be semantically valid
  for (const sp of P.board) {
    if (sp.type === 'property' || sp.type === 'station' || sp.type === 'utility') {
      const state = titleToNftState(s, sp.id, ctx);
      assert.ok(validateTitleSemantics(state).ok, `${sp.id} (${sp.type}) valid`);
    }
  }
  // a title whose groupId does not match its property is rejected
  const good = titleToNftState(s, 1, ctx);
  assert.equal(validateTitleSemantics({ ...good, groupId: good.groupId + 7 }).ok, false);
  // a non-board propertyId is rejected
  assert.equal(validateTitleSemantics({ ...good, propertyId: 39, groupId: 0 }).ok, validateTitleSemantics({ ...good, propertyId: 39, groupId: 0 }).ok);
  // a station/utility with a building is rejected
  const station = P.board.find((b) => b.type === 'station');
  if (station) {
    const st = titleToNftState(s, station.id, ctx);
    assert.equal(validateTitleSemantics({ ...st, buildLevel: 2 }).ok, false, 'stations cannot build');
  }
});

// ---- #1: bank custody = covenant by default; seat custody = fresh provider key --
test('bank reserve leg is COVENANT-locked by default (no reused bankPkh)', async () => {
  const { covenantOutput, rulesHash } = await import('@estates/bank');
  const { bankValueOutput } = await import('../src/index.ts');
  const cov = bankValueOutput(500, ctx);                       // default mode = covenant
  assert.deepEqual(cov, covenantOutput(500, rulesHash(ctx.gameId)), 'bank value is the game-bound self-enforcing covenant output');
  // it is NOT a plain P2PKH to the static bankPkh
  const { paymentOutput } = await import('@estates/onchain');
  assert.notDeepEqual(cov.script, paymentOutput(500, ctx.bankPkh).script, 'not a reused-pkh payment');
});

test('quorum is opt-in: bankMode "quorum" pays the banker pkh (M-of-N)', async () => {
  const { paymentOutput } = await import('@estates/onchain');
  const { bankValueOutput } = await import('../src/index.ts');
  const q = bankValueOutput(500, { ...ctx, bankMode: 'quorum' });
  assert.deepEqual(q, paymentOutput(500, ctx.bankPkh), 'quorum mode → P2PKH to the banker');
});

test('owned-title NFT custody uses the FRESH provider key, never the static seat pkh', () => {
  let s = initialState(cfg);
  s = setOwner(s, [1], 0);                                     // seat 0 owns title 1
  const fresh = new Uint8Array(20).fill(0xab);
  const calls: string[] = [];
  const provider = (role: number, purpose: string) => { calls.push(`${role}:${purpose}`); return fresh; };
  const out = titleToNftOutput(s, 1, ctx, provider);
  assert.ok(calls.includes('0:nft'), 'derived a one-use NFT-custody key for the owner');
  // the custody is the fresh key, not ctx.seatPkhs[0]
  const stale = titleToNftOutput(s, 1, ctx);                  // no provider → legacy seat pkh
  assert.notDeepEqual(out.script, stale.script, 'provider key differs from the static seat pkh');
});

test('a bank-held (unowned) title NFT is covenant-locked, not bankPkh', async () => {
  const { covenantScriptItems, rulesHash } = await import('@estates/bank');
  const { nftOutputWith } = await import('@estates/onchain');
  const s = initialState(cfg);                                // all titles unowned at start
  const out = titleToNftOutput(s, 1, ctx);                    // owner === null
  const expected = nftOutputWith(titleToNftState(s, 1, ctx), covenantScriptItems(rulesHash(ctx.gameId)));
  assert.deepEqual(out.script, expected.script, 'bank-held NFT sits under the covenant');
});
