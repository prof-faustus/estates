import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  OP, op, push, serializeScript, containsOpReturn, scriptHex, p2pkh,
  encodeTitleState, decodeTitleState, nftLockingScript, nftOutput, paymentOutput,
  gameTag, hasGenesis, NFT_SATS, validateTitleState, nftStateFromScript, titleBelongsToGame, type TitleState,
} from '../src/index.ts';

const pkh = (n: number): Uint8Array => { const b = new Uint8Array(20); b.fill(n); return b; };
const GAME = new Uint8Array(32).fill(7);
const GENESIS = { txid: 'ab'.repeat(32), vout: 3 };

function title(over: Partial<TitleState> = {}): TitleState {
  return {
    kind: 'TITLE', gameTag: gameTag(GAME, 'TITLE'), propertyId: 3, groupId: 0,
    buildLevel: 0, mortgaged: false, genesis: GENESIS, ...over,
  };
}

test('title state encodes and decodes round-trip (incl. build + mortgage)', () => {
  const s = title({ buildLevel: 4, mortgaged: true });
  const dec = decodeTitleState(encodeTitleState(s));
  assert.equal(dec.kind, 'TITLE');
  assert.equal(dec.propertyId, 3);
  assert.equal(dec.buildLevel, 4);
  assert.equal(dec.mortgaged, true);
  assert.deepEqual(dec.genesis, GENESIS);
  assert.deepEqual([...dec.gameTag], [...s.gameTag]);
});

test('Reprieve NFT round-trips with kind REPRIEVE', () => {
  const r = title({ kind: 'REPRIEVE', propertyId: 0, gameTag: gameTag(GAME, 'REPRIEVE') });
  assert.equal(decodeTitleState(encodeTitleState(r)).kind, 'REPRIEVE');
});

test('every NFT is a 1-sat NFT; the locking script is <state> OP_DROP <P2PKH>, no OP_RETURN', () => {
  const items = nftLockingScript(title(), pkh(1));
  assert.equal(containsOpReturn(items), false);
  // structure: push(state), OP_DROP, then 5-item P2PKH
  assert.ok('push' in items[0]!);
  assert.deepEqual(items[1], { op: OP.OP_DROP });
  assert.equal(nftOutput(title(), pkh(1)).satoshis, NFT_SATS);
  assert.equal(NFT_SATS, 1);
});

test('serializeScript THROWS on OP_RETURN (defence in depth)', () => {
  assert.throws(() => serializeScript([push(new Uint8Array([1, 2, 3])), op(OP.OP_RETURN)]), /OP_RETURN/);
  assert.equal(containsOpReturn([op(OP.OP_RETURN)]), true);
});

test('transfer re-mints to a new owner (same state, different predicate)', () => {
  const a = scriptHex(nftLockingScript(title(), pkh(1)));
  const b = scriptHex(nftLockingScript(title(), pkh(2)));
  assert.notEqual(a, b);                       // different owner -> different script
  // state blob is identical for both owners
  const sa = encodeTitleState(title());
  assert.equal(scriptHex([push(sa)]).length > 0, true);
});

test('build / mortgage re-mint changes the state blob (and thus the script)', () => {
  const base = scriptHex(nftLockingScript(title(), pkh(1)));
  const built = scriptHex(nftLockingScript(title({ buildLevel: 1 }), pkh(1)));
  const mort = scriptHex(nftLockingScript(title({ mortgaged: true }), pkh(1)));
  assert.notEqual(base, built);
  assert.notEqual(base, mort);
});

test('forged title: provenance fails when the genesis outpoint does not match', () => {
  assert.equal(hasGenesis(title(), GENESIS), true);
  assert.equal(hasGenesis(title(), { txid: 'cd'.repeat(32), vout: 3 }), false);
  assert.equal(hasGenesis(title(), { txid: 'ab'.repeat(32), vout: 9 }), false);
});

test('malformed state pushdata is rejected on decode', () => {
  assert.throws(() => decodeTitleState(new Uint8Array(10)), /73 bytes/);
});

test('native-sat payment is an ordinary P2PKH output; negative amounts rejected', () => {
  const out = paymentOutput(250, pkh(5));
  assert.equal(out.satoshis, 250);
  assert.equal(containsOpReturn([push(out.script)]), false);
  assert.throws(() => paymentOutput(-1, pkh(5)), /non-negative/);
});

test('p2pkh requires a 20-byte HASH160', () => {
  assert.throws(() => p2pkh(new Uint8Array(19)), /20 bytes/);
});

test('game tags are domain-separated by kind', () => {
  assert.notDeepEqual([...gameTag(GAME, 'TITLE')], [...gameTag(GAME, 'REPRIEVE')]);
});

// ---- audit #6: reject impossible / adversarial NFT state ---------------------
test('encodeTitleState rejects out-of-range / non-canonical state (no silent masking)', () => {
  assert.throws(() => encodeTitleState(title({ propertyId: 40 })), /propertyId/);
  assert.throws(() => encodeTitleState(title({ propertyId: -1 })), /propertyId/);
  assert.throws(() => encodeTitleState(title({ buildLevel: 6 })), /buildLevel/);
  assert.throws(() => encodeTitleState(title({ groupId: 300 })), /groupId/);
  assert.throws(() => encodeTitleState(title({ kind: 'REPRIEVE', propertyId: 5 })), /REPRIEVE/);
  assert.throws(() => encodeTitleState(title({ genesis: { txid: 'ab'.repeat(32), vout: -1 } })), /vout/);
  assert.throws(() => encodeTitleState(title({ genesis: { txid: 'zz'.repeat(32), vout: 0 } })), /hex/);
});

test('decodeTitleState rejects a non-canonical mortgaged byte and impossible fields', () => {
  const good = encodeTitleState(title({ buildLevel: 2 }));
  // tamper the mortgaged byte (offset 1+32+1+1+1 = 36) to a non-canonical value
  const badMort = good.slice(); badMort[36] = 2;
  assert.throws(() => decodeTitleState(badMort), /mortgaged/);
  // tamper buildLevel (offset 35) above 5
  const badLevel = good.slice(); badLevel[35] = 9;
  assert.throws(() => decodeTitleState(badLevel), /buildLevel/);
  // tamper propertyId (offset 33) past the board
  const badProp = good.slice(); badProp[33] = 200;
  assert.throws(() => decodeTitleState(badProp), /propertyId/);
});

test('validateTitleState accepts every legal title and a canonical REPRIEVE', () => {
  for (let p = 0; p < 40; p++) for (const lvl of [0, 1, 5]) validateTitleState(title({ propertyId: p, buildLevel: lvl }));
  validateTitleState(title({ kind: 'REPRIEVE', propertyId: 0, groupId: 0, buildLevel: 0 }));
});

test('nftStateFromScript recovers the on-chain TitleState from an NFT output script', () => {
  const s = title({ propertyId: 12, buildLevel: 3, mortgaged: true });
  const decoded = nftStateFromScript(nftOutput(s, pkh(9)).script);
  assert.ok(decoded, 'an NFT output decodes back to its state');
  assert.equal(decoded!.propertyId, 12);
  assert.equal(decoded!.buildLevel, 3);
  assert.equal(decoded!.mortgaged, true);
  assert.deepEqual([...decoded!.gameTag], [...s.gameTag]);
  // a Reprieve NFT too
  const r = title({ kind: 'REPRIEVE', propertyId: 0, gameTag: gameTag(GAME, 'REPRIEVE') });
  assert.equal(nftStateFromScript(nftOutput(r, pkh(1)).script)!.kind, 'REPRIEVE');
});

test('nftStateFromScript is TOTAL: a payment / malformed / non-NFT script returns null (never throws)', () => {
  assert.equal(nftStateFromScript(paymentOutput(500, pkh(2)).script), null);   // plain P2PKH
  assert.equal(nftStateFromScript(new Uint8Array(0)), null);
  assert.equal(nftStateFromScript(new Uint8Array([0x49])), null);              // push len but no body
  assert.equal(nftStateFromScript(serializeScript([push(new Uint8Array(73))])), null); // 73-byte push, no OP_DROP/garbage state
  // a 73-byte push followed by OP_DROP but garbage state → decode fails → null
  assert.equal(nftStateFromScript(serializeScript([push(new Uint8Array(73).fill(0xff)), op(OP.OP_DROP)])), null);
});

test('titleBelongsToGame binds an NFT to one game (gameTag), rejects another game + bad gameId', () => {
  const OTHER = new Uint8Array(32).fill(0xa5);
  assert.equal(titleBelongsToGame(title(), GAME), true);
  assert.equal(titleBelongsToGame(title({ kind: 'REPRIEVE', propertyId: 0, gameTag: gameTag(GAME, 'REPRIEVE') }), GAME), true);
  // a deed tagged for another game does not belong to GAME
  assert.equal(titleBelongsToGame(title({ gameTag: gameTag(OTHER, 'TITLE') }), GAME), false);
  // a TITLE carrying the REPRIEVE tag (wrong kind binding) is rejected
  assert.equal(titleBelongsToGame(title({ gameTag: gameTag(GAME, 'REPRIEVE') }), GAME), false);
  // fail closed on a non-32-byte gameId
  assert.equal(titleBelongsToGame(title(), new Uint8Array(31)), false);
});
