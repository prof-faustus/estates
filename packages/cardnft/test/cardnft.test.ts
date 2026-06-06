// A card is a FULL 1-sat BSV NFT (UTXO). A transfer SPENDS Alice's outpoint and
// creates Bob's successor 1-sat NFT — so Alice's card is on-chain DEAD. These are
// the audit's exact required tests (old card not live, retained copy rejected,
// resurrection rejected, UTXO successor continuity, TEE quote).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256, ripemd160, bytesToHex } from '@estates/keys';
import { genCardKey, mintCard, type CardFace } from '@estates/deck';
import { txid } from '@estates/tx';
import {
  mintCardNft, transferCardNft, verifyCardTransfer, isLiveCard, opKey,
  verifyTeeDeletionQuote, cardNftOutput, verifyCardCustodyChain, deckToNfts, verifyDeckNfts, type Outpoint, type CardNft,
} from '../src/index.ts';

const TABLE = 'a1'.repeat(32);
const face: CardFace = { kind: 'TITLE', id: 5 };
const hash160 = (pub: Uint8Array) => ripemd160(sha256(pub));

function aliceCard(): { nft: CardNft; concealed: ReturnType<typeof mintCard>['card']; secret: ReturnType<typeof mintCard>['secret']; aliceHolder: ReturnType<typeof genCardKey> } {
  const aliceHolder = genCardKey();
  const { card, secret } = mintCard(TABLE, face, aliceHolder.pub);
  const aliceOwnerPkh = hash160(aliceHolder.pub);
  const genesisOutpoint: Outpoint = { txid: 'ff'.repeat(32), vout: 3 };
  const nft = mintCardNft(card, aliceOwnerPkh, genesisOutpoint);
  return { nft, concealed: card, secret, aliceHolder };
}

test('a card NFT is a real 1-sat UTXO with an outpoint + identity-committing script', () => {
  const { nft } = aliceCard();
  assert.equal(nft.satoshis, 1);
  assert.ok(nft.outpoint.txid.length === 64 && nft.outpoint.vout >= 0);
  // its on-chain output commits to the card identity, locked to the owner pkh
  const out = cardNftOutput(nft.tableId, nft.commitment, nft.cardPub, Buffer.from(nft.ownerPkh, 'hex'));
  assert.equal(out.satoshis, 1);
  assert.ok(out.script.length > 20);
});

test('transfer SPENDS Alice’s outpoint and creates Bob’s successor 1-sat NFT (UTXO continuity)', () => {
  const { nft, concealed, secret } = aliceCard();
  const bobHolder = genCardKey();
  const bobPkh = hash160(bobHolder.pub);
  const t = transferCardNft(nft, concealed, secret.face, bobHolder.pub, bobPkh);

  // the tx spends Alice's exact card outpoint
  assert.ok(t.tx.inputs.some((i) => i.prevTxid === nft.outpoint.txid && i.prevVout === nft.outpoint.vout), 'Alice’s outpoint is spent');
  // Bob's successor is a fresh 1-sat NFT at a new outpoint with a fresh key
  assert.equal(t.newCard.satoshis, 1);
  assert.equal(t.newCard.outpoint.txid, txid(t.tx));
  assert.notEqual(t.newCard.cardPub, nft.cardPub, 'fresh one-use key');
  assert.equal(t.newCard.commitment, nft.commitment, 'same concealed identity carries over');
  // and the structural verifier accepts it
  assert.ok(verifyCardTransfer(t.tx, nft, bobPkh, t.newCard).ok);
});

test('Alice’s old card is DEAD after transfer; Bob’s is LIVE', () => {
  const { nft, concealed, secret } = aliceCard();
  const bobHolder = genCardKey(); const bobPkh = hash160(bobHolder.pub);
  const t = transferCardNft(nft, concealed, secret.face, bobHolder.pub, bobPkh);
  const spent = new Set([opKey(t.spent)]); // the chain marks Alice's outpoint spent
  assert.equal(isLiveCard(nft, spent), false, 'Alice’s old card UTXO is spent/dead');
  assert.equal(isLiveCard(t.newCard, spent), true, 'Bob’s successor is live');
});

test('a "transfer" that does NOT spend Alice’s outpoint is REJECTED as a copy', () => {
  const { nft, concealed, secret } = aliceCard();
  const bobHolder = genCardKey(); const bobPkh = hash160(bobHolder.pub);
  const t = transferCardNft(nft, concealed, secret.face, bobHolder.pub, bobPkh);
  // forge a tx that creates Bob's output but spends some OTHER outpoint (not Alice's)
  const forged = { ...t.tx, inputs: [{ prevTxid: '00'.repeat(32), prevVout: 0, scriptSig: new Uint8Array(0), sequence: 0xffffffff }] };
  assert.equal(verifyCardTransfer(forged, nft, bobPkh, t.newCard).ok, false);
});

test('a successor that reuses Alice’s retired key, wrong owner, or changed identity is REJECTED', () => {
  const { nft, concealed, secret } = aliceCard();
  const bobHolder = genCardKey(); const bobPkh = hash160(bobHolder.pub);
  const t = transferCardNft(nft, concealed, secret.face, bobHolder.pub, bobPkh);
  // reused retired key
  assert.equal(verifyCardTransfer(t.tx, nft, bobPkh, { ...t.newCard, cardPub: nft.cardPub }).ok, false);
  // locked to a different owner than the output actually pays
  const mallory = hash160(genCardKey().pub);
  assert.equal(verifyCardTransfer(t.tx, nft, mallory, t.newCard).ok, false);
  // changed concealed identity
  assert.equal(verifyCardTransfer(t.tx, nft, bobPkh, { ...t.newCard, commitment: 'bb'.repeat(32) }).ok, false);
});

test('a SPENT card cannot be resurrected: a transcript with the retired key/outpoint is rejected', () => {
  const { nft, concealed, secret } = aliceCard();
  const bobHolder = genCardKey(); const bobPkh = hash160(bobHolder.pub);
  const t = transferCardNft(nft, concealed, secret.face, bobHolder.pub, bobPkh);
  const spent = new Set([opKey(t.spent)]);
  // Alice re-presents her old card (same retired outpoint) → not live
  const resurrected: CardNft = { ...nft };
  assert.equal(isLiveCard(resurrected, spent), false, 'a spent outpoint never becomes live again');
  // and a "successor" reusing the retired outpoint as if fresh is caught by the spent set
  assert.ok(spent.has(opKey(nft.outpoint)));
});

test('TEE deletion quote (assumed OK) binds the retired key + spent outpoint', () => {
  const { nft, concealed, secret } = aliceCard();
  const bobHolder = genCardKey(); const bobPkh = hash160(bobHolder.pub);
  const quote = { retiredCardPub: nft.cardPub, spent: nft.outpoint, attestation: 'tee-attestation-blob-0123456789' };
  const t = transferCardNft(nft, concealed, secret.face, bobHolder.pub, bobPkh, JSON.stringify(quote));
  assert.ok(t.teeDeletionQuote, 'transfer carries the quote');
  assert.ok(verifyTeeDeletionQuote(quote, t.retiredCardPub, t.spent).ok);
  // a quote that does not bind this retired key / outpoint is rejected
  assert.equal(verifyTeeDeletionQuote({ ...quote, retiredCardPub: 'cc'.repeat(33) }, t.retiredCardPub, t.spent).ok, false);
  assert.equal(verifyTeeDeletionQuote(null, t.retiredCardPub, t.spent).ok, false);
  void bytesToHex;
});

test('a whole custody chain (mint→Alice→Bob→Carol) is a sequence of true moves; final live card is Carol’s', () => {
  const { nft, concealed, secret } = aliceCard();
  const bob = genCardKey(); const bobPkh = hash160(bob.pub);
  const carol = genCardKey(); const carolPkh = hash160(carol.pub);
  // mint already to Alice; transfer Alice→Bob
  const t1 = transferCardNft(nft, concealed, secret.face, bob.pub, bobPkh);
  // rebuild Bob's ConcealedCard from t1.newCard to transfer again (same face/identity)
  const bobConcealed = { tableId: t1.newCard.tableId, cardPub: t1.newCard.cardPub, commitment: t1.newCard.commitment, sealed: t1.newCard.sealed };
  const t2 = transferCardNft(t1.newCard, bobConcealed, secret.face, carol.pub, carolPkh);
  const chain = verifyCardCustodyChain(nft, [t1, t2]);
  assert.ok(chain.ok, chain.reason);
  assert.equal(chain.live!.outpoint.txid, t2.newCard.outpoint.txid, 'final live card is Carol’s');
});

test('the custody chain REJECTS a re-spend of an already-spent outpoint (resurrection)', () => {
  const { nft, concealed, secret } = aliceCard();
  const bob = genCardKey(); const bobPkh = hash160(bob.pub);
  const t1 = transferCardNft(nft, concealed, secret.face, bob.pub, bobPkh);
  // a second transfer that ILLEGALLY spends the SAME (already-spent) Alice outpoint again
  const t2bad = transferCardNft(nft, concealed, secret.face, genCardKey().pub, hash160(genCardKey().pub));
  assert.equal(verifyCardCustodyChain(nft, [t1, t2bad]).ok, false, 'cannot spend Alice’s outpoint twice');
});

test('the custody chain REJECTS a transfer that does not spend the current live card', () => {
  const { nft, concealed, secret } = aliceCard();
  const bob = genCardKey(); const bobPkh = hash160(bob.pub);
  const t1 = transferCardNft(nft, concealed, secret.face, bob.pub, bobPkh);
  // forge t1 to spend some unrelated outpoint
  const forged = { ...t1, spent: { txid: '00'.repeat(32), vout: 9 } };
  assert.equal(verifyCardCustodyChain(nft, [forged]).ok, false);
});

test('a whole concealed DECK becomes a set of real 1-sat card NFTs (unique UTXOs + keys)', async () => {
  const { mintDeck } = await import('@estates/deck');
  const dealer = genCardKey();
  const dealerPkh = hash160(dealer.pub);
  const faces: CardFace[] = Array.from({ length: 8 }, (_, i) => ({ kind: 'FATE', id: i }));
  const minted = mintDeck(TABLE, faces, dealer.pub, new Uint8Array(32).fill(3));
  const outpoints: Outpoint[] = minted.cards.map((_, i) => ({ txid: 'cc'.repeat(32), vout: i }));
  const nfts = deckToNfts(minted.cards, dealerPkh, outpoints);
  assert.equal(nfts.length, 8);
  assert.ok(verifyDeckNfts(nfts, TABLE).ok, 'every card is a 1-sat NFT, unique UTXO + key');
  // a deck with a duplicated outpoint or key is rejected
  assert.equal(verifyDeckNfts([nfts[0]!, { ...nfts[1]!, outpoint: nfts[0]!.outpoint }], TABLE).ok, false);
  assert.equal(verifyDeckNfts([nfts[0]!, { ...nfts[1]!, cardPub: nfts[0]!.cardPub }], TABLE).ok, false);
  // wrong table rejected
  assert.equal(verifyDeckNfts(nfts, 'b2'.repeat(32)).ok, false);
});
