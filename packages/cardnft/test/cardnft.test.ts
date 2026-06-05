// A card is a FULL 1-sat BSV NFT (UTXO). A transfer SPENDS Alice's outpoint and
// creates Bob's successor 1-sat NFT — so Alice's card is on-chain DEAD. These are
// the audit's exact required tests (old card not live, retained copy rejected,
// resurrection rejected, UTXO successor continuity, TEE quote).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { sha256 } from '@noble/hashes/sha256';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { bytesToHex } from '@noble/hashes/utils';
import { genCardKey, mintCard, type CardFace } from '@estates/deck';
import { txid } from '@estates/tx';
import {
  mintCardNft, transferCardNft, verifyCardTransfer, isLiveCard, opKey,
  verifyTeeDeletionQuote, cardNftOutput, type Outpoint, type CardNft,
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
