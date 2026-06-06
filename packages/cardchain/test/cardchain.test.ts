/**
 * The LIVE card-NFT lifecycle: the Fate/Treasury decks are real 1-sat BSV NFTs, and every
 * draw/pass SPENDS the current outpoint and re-seals the face to the new holder — so the
 * previous holder LOSES access. Every claim has a positive + a hostile negative case.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { genCardKey } from '@estates/deck';
import { verifyCardTransfer, verifyCardCustodyChain } from '@estates/cardnft';
import { mintCardDeck, passCard, openHeld, holderPkh, verifyDeckNfts, isLiveCard, deckFaces } from '../src/index.ts';

const GID = 'a1'.repeat(32);
const spentSet = (...nfts: { outpoint: { txid: string; vout: number } }[]) => new Set(nfts.map((n) => `${n.outpoint.txid}:${n.outpoint.vout}`));
// distinct 64-hex outpoint txids, one per deck position
const outpointsFor = (prefix: string, n: number) =>
  Array.from({ length: n }, (_, i) => ({ txid: (prefix + i.toString(16)).padStart(2, '0').repeat(32).slice(0, 64), vout: 0 }));

test('a deck is minted as REAL 1-sat card NFTs (bank-held): unique UTXOs + one-use keys', () => {
  const bank = genCardKey();
  const faces = deckFaces('Fate');
  const order = faces.map((_, i) => i);
  const { nfts } = mintCardDeck(GID, 'Fate', order, bank.pub, holderPkh(bank.pub), outpointsFor('0', faces.length));
  assert.equal(nfts.length, faces.length, 'one NFT per card');
  const v = verifyDeckNfts(nfts, GID);
  assert.ok(v.ok, v.reason);
  for (const n of nfts) { assert.equal(n.satoshis, 1); assert.equal(n.tableId, GID); }
  // a deck verified against a DIFFERENT game is rejected (table-bound)
  assert.equal(verifyDeckNfts(nfts, 'b2'.repeat(32)).ok, false);
});

test('a DRAW spends the bank outpoint + re-seals to the player; the BANK loses access, the player gains it', () => {
  const bank = genCardKey(), alice = genCardKey();
  const faces = deckFaces('Fate');
  const { nfts, secrets } = mintCardDeck(GID, 'Fate', faces.map((_, i) => i), bank.pub, holderPkh(bank.pub), outpointsFor('0', faces.length));
  const card0 = nfts[0]!, sec0 = secrets[0]!;
  assert.ok(openHeld(card0, bank.priv, sec0.blind), 'the bank can open the card it holds');

  // draw: a real transfer bank → Alice (SPENDS the bank's 1-sat card outpoint)
  const t = passCard(card0, sec0, alice.pub, holderPkh(alice.pub));
  assert.ok(verifyCardTransfer(t.tx, card0, holderPkh(alice.pub), t.newCard).ok, 'spends bank outpoint → Alice successor');

  // Alice can now open it; the BANK can NO LONGER (the face was re-sealed to Alice)
  assert.deepEqual(openHeld(t.newCard, alice.priv, sec0.blind), sec0.face, 'Alice gains access (re-sealed to her)');
  assert.equal(openHeld(t.newCard, bank.priv, sec0.blind), null, 'the bank LOSES access — it cannot decrypt Alice’s seal');

  // the bank's old card UTXO is on-chain DEAD; Alice's successor is live
  const spent = spentSet(card0);
  assert.equal(isLiveCard(card0, spent), false, 'the spent card is dead');
  assert.equal(isLiveCard(t.newCard, spent), true, 'Alice’s successor is live');
});

test('Alice → Bob: spends Alice’s outpoint, re-seals to Bob; Alice LOSES access; the custody chain verifies', () => {
  const bank = genCardKey(), alice = genCardKey(), bob = genCardKey();
  const faces = deckFaces('Treasury');
  const { nfts, secrets } = mintCardDeck(GID, 'Treasury', faces.map((_, i) => i), bank.pub, holderPkh(bank.pub), outpointsFor('a', faces.length));
  const mint = nfts[0]!, sec = secrets[0]!;

  const toAlice = passCard(mint, sec, alice.pub, holderPkh(alice.pub));   // bank → Alice
  const toBob = passCard(toAlice.newCard, sec, bob.pub, holderPkh(bob.pub)); // Alice → Bob

  // Bob can open the card; Alice can NO LONGER (it was re-sealed to Bob) — she lost access
  assert.deepEqual(openHeld(toBob.newCard, bob.priv, sec.blind), sec.face, 'Bob gains access');
  assert.equal(openHeld(toBob.newCard, alice.priv, sec.blind), null, 'Alice LOSES access when the card is sent to Bob');

  // the Alice→Bob tx really spends Alice's outpoint (not a copy)
  assert.ok(verifyCardTransfer(toBob.tx, toAlice.newCard, holderPkh(bob.pub), toBob.newCard).ok);

  // the whole chain mint → Alice → Bob is a sequence of TRUE moves (no copy/double-spend/resurrection)
  const chain = verifyCardCustodyChain(mint, [toAlice, toBob]);
  assert.ok(chain.ok, chain.reason);
  assert.equal(chain.live?.outpoint.txid, toBob.newCard.outpoint.txid, 'the final live card is Bob’s');

  // every earlier outpoint is dead; only Bob's is live
  const spent = spentSet(mint, toAlice.newCard);
  assert.equal(isLiveCard(mint, spent), false);
  assert.equal(isLiveCard(toAlice.newCard, spent), false);
  assert.equal(isLiveCard(toBob.newCard, spent), true);
});

test('a re-spend of an already-spent card (resurrection) is REJECTED by the custody chain', () => {
  const bank = genCardKey(), alice = genCardKey(), bob = genCardKey();
  const faces = deckFaces('Fate');
  const { nfts, secrets } = mintCardDeck(GID, 'Fate', faces.map((_, i) => i), bank.pub, holderPkh(bank.pub), outpointsFor('c', faces.length));
  const mint = nfts[0]!, sec = secrets[0]!;
  const toAlice = passCard(mint, sec, alice.pub, holderPkh(alice.pub));
  // try to spend the ORIGINAL (already-spent) mint again instead of Alice's live card
  const resurrect = passCard(mint, sec, bob.pub, holderPkh(bob.pub));
  const chain = verifyCardCustodyChain(mint, [toAlice, resurrect]);
  assert.equal(chain.ok, false, 'spending the dead mint outpoint again is rejected');
});
