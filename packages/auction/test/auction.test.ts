import { test } from 'node:test';
import assert from 'node:assert/strict';
import { commitBid, revealValid, resolveAuction, type Commitment, type Reveal } from '../src/index.ts';

const nonce = (n: number): Uint8Array => { const b = new Uint8Array(16); b[0] = n; b[15] = n ^ 0x5a; return b; };
const commit = (seat: number, bid: number): Commitment => ({ seat, hash: commitBid(seat, bid, nonce(seat)) });
const reveal = (seat: number, bid: number): Reveal => ({ seat, bid, nonce: nonce(seat) });

test('commit/reveal round-trip; forged reveal (wrong bid) is invalid', () => {
  const c = commit(0, 120);
  assert.equal(revealValid(c, reveal(0, 120)), true);
  assert.equal(revealValid(c, reveal(0, 999)), false); // changed bid
  assert.equal(revealValid(c, { seat: 0, bid: 120, nonce: nonce(1) }), false); // wrong nonce
});

test('sealed: the commitment hides the bid (different bids -> different commits)', () => {
  assert.notDeepEqual([...commitBid(0, 100, nonce(0))], [...commitBid(0, 101, nonce(0))]);
});

test('highest valid bid wins; losers reported', () => {
  const commits = [commit(0, 100), commit(1, 220), commit(2, 150)];
  const reveals = [reveal(0, 100), reveal(1, 220), reveal(2, 150)];
  const out = resolveAuction(commits, reveals);
  assert.deepEqual(out, { sold: true, winner: 1, price: 220, losers: [0, 2] });
});

test('ties break to the lowest seat', () => {
  const commits = [commit(2, 200), commit(0, 200), commit(1, 200)];
  const reveals = [reveal(2, 200), reveal(0, 200), reveal(1, 200)];
  const out = resolveAuction(commits, reveals);
  assert.ok(out.sold && out.winner === 0 && out.price === 200);
});

test('committed non-revealer is dropped; a revealed lower bid then wins', () => {
  const commits = [commit(0, 300), commit(1, 120)];
  // seat 0 never reveals (timeout); only seat 1 reveals
  const out = resolveAuction(commits, [reveal(1, 120)]);
  assert.ok(out.sold && out.winner === 1 && out.price === 120);
});

test('a reveal not matching its commitment cannot steal the win', () => {
  const commits = [commit(0, 100), commit(1, 120)];
  // seat 1 tries to inflate its revealed bid beyond what it committed
  const out = resolveAuction(commits, [reveal(0, 100), { seat: 1, bid: 999, nonce: nonce(1) }]);
  assert.ok(out.sold && out.winner === 0 && out.price === 100); // forged reveal dropped
});

test('no valid bids -> unsold (returns to bank)', () => {
  const commits = [commit(0, 100)];
  const out = resolveAuction(commits, []); // nobody revealed
  assert.deepEqual(out, { sold: false, reason: 'no-valid-bids' });
});

test('bids must be non-negative integers; nonce must be ≥16 bytes', () => {
  assert.throws(() => commitBid(0, -5, nonce(0)), /non-negative/);
  assert.throws(() => commitBid(0, 10, new Uint8Array(8)), /16 bytes/);
});
