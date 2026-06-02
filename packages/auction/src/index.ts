/**
 * @estates/auction — sealed-bid auction (D-AUCTION; S3a of the turn FSM).
 *
 * Two phases, mirroring the dice beacon (binds C4/C6): each seat publishes a
 * commitment c = SHA-256( bid ‖ nonce ‖ seat ), then reveals (bid, nonce). The
 * bid is concealed until reveal (sealed-bid). The highest VALID revealed bid
 * wins; ties break to the lowest seat. A commitment with no valid reveal is
 * dropped (the timeout default). If no valid bids, the property is unsold and
 * returns to the bank. The winner pays its bid to the bank reserve and receives
 * the 1-sat title NFT (atomic settle — see @estates/trade for the tx shape).
 */
import { createHash } from 'node:crypto';

export interface Commitment { readonly seat: number; readonly hash: Uint8Array; }
export interface Reveal { readonly seat: number; readonly bid: number; readonly nonce: Uint8Array; }

function u64be(n: number): Uint8Array {
  const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b;
}

/** Sealed commitment to a bid: SHA-256(bid ‖ nonce ‖ seat). */
export function commitBid(seat: number, bid: number, nonce: Uint8Array): Uint8Array {
  if (!Number.isInteger(bid) || bid < 0) throw new Error('bid must be a non-negative integer (sats)');
  if (nonce.length < 16) throw new Error('nonce must be ≥16 bytes');
  return new Uint8Array(createHash('sha256').update(u64be(bid)).update(nonce).update(Uint8Array.from([seat & 0xff])).digest());
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i]! ^ b[i]!; return d === 0;
}

/** A reveal is valid iff it hashes back to the seat's commitment. */
export function revealValid(commit: Commitment, reveal: Reveal): boolean {
  return commit.seat === reveal.seat && eq(commitBid(reveal.seat, reveal.bid, reveal.nonce), commit.hash);
}

export type AuctionOutcome =
  | { readonly sold: true; readonly winner: number; readonly price: number; readonly losers: readonly number[] }
  | { readonly sold: false; readonly reason: 'no-valid-bids' };

/**
 * Resolve the auction. Only reveals matching their commitment count. Highest
 * bid wins; ties break to the lowest seat. A zero bid is a valid bid only if it
 * is the sole entry (otherwise any positive bid beats it). No valid bids → unsold.
 */
export function resolveAuction(commits: readonly Commitment[], reveals: readonly Reveal[]): AuctionOutcome {
  const byseat = new Map(commits.map((c) => [c.seat, c]));
  const valid = reveals.filter((r) => {
    const c = byseat.get(r.seat);
    return c !== undefined && revealValid(c, r);
  });
  if (valid.length === 0) return { sold: false, reason: 'no-valid-bids' };

  let best = valid[0]!;
  for (const r of valid) {
    if (r.bid > best.bid || (r.bid === best.bid && r.seat < best.seat)) best = r;
  }
  const losers = valid.filter((r) => r.seat !== best.seat).map((r) => r.seat).sort((a, b) => a - b);
  return { sold: true, winner: best.seat, price: best.bid, losers };
}
