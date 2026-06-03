/**
 * @estates/beacon — provably-fair dice (tx-nft doc §5), binding C4.
 *
 * Two-phase per roll: every active seat publishes c_i = SHA-256(secret_i)
 * (commit), then reveals secret_i. The dice are a DEBIASED map (rejection
 * sampling, removing modulo bias) of
 *     H( reveal_1 ‖ … ‖ reveal_n ‖ turn_index ‖ prev_beacon )
 * into two integers in [1..6]. `prev_beacon` chains rolls into one verifiable
 * transcript. Unbiasable iff ≥1 honest seat commits before any reveal; a
 * committed non-revealer's reveal is dropped (timeout default) as long as ≥1
 * honest reveal remains.
 *
 * The crypto here (SHA-256 commit, HMAC-SHA256 counter PRF) is algorithmically
 * identical to @bsv-poker/crypto-mentalpoker (entropyCommitSync /
 * permutationFromEntropy). PROTOCOL-BINDING.md records the intent to swap to a
 * direct import once cross-repo workspace linking is wired.
 */
import { sha256 as nobleSha256 } from '@noble/hashes/sha256';
import { hmac } from '@noble/hashes/hmac';

export const ZERO_BEACON: Uint8Array = new Uint8Array(32);

function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let len = 0; for (const p of parts) len += p.length;
  const out = new Uint8Array(len); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export interface PartyReveal {
  readonly seat: number;
  readonly secret: Uint8Array; // the committed preimage
}

export interface BeaconResult {
  readonly dice: readonly [number, number];
  readonly total: number;
  readonly beacon: Uint8Array;       // becomes prev_beacon for the next roll
  readonly contributors: readonly number[]; // seats whose reveals were used
}

function sha256(...parts: Uint8Array[]): Uint8Array {
  return nobleSha256(concatBytes(...parts));
}

/** Commitment to a secret: c = SHA-256(secret). Mirrors entropyCommitSync. */
export function commit(secret: Uint8Array): Uint8Array {
  return sha256(secret);
}

/** Constant-time-ish check that a revealed secret matches its commitment. */
export function verifyReveal(secret: Uint8Array, commitment: Uint8Array): boolean {
  const c = commit(secret);
  if (c.length !== commitment.length) return false;
  let diff = 0;
  for (let i = 0; i < c.length; i++) diff |= c[i]! ^ commitment[i]!;
  return diff === 0;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  b[0] = (n >>> 24) & 0xff; b[1] = (n >>> 16) & 0xff; b[2] = (n >>> 8) & 0xff; b[3] = n & 0xff;
  return b;
}

/**
 * Combined seed = H( reveals(in ascending seat order) ‖ turn_index ‖ prev_beacon ).
 * Seat-ordering makes it canonical and non-manipulable; order-independent of
 * arrival.
 */
export function beaconSeed(reveals: readonly PartyReveal[], turnIndex: number, prevBeacon: Uint8Array): Uint8Array {
  const ordered = [...reveals].sort((a, b) => a.seat - b.seat);
  const parts: Uint8Array[] = ordered.map((r) => r.secret);
  parts.push(u32be(turnIndex), prevBeacon);
  return sha256(...parts);
}

/**
 * Draw one unbiased die [1..6] from the seed using an HMAC-SHA256 counter PRF
 * with rejection sampling: reject bytes ≥ 252 (the largest multiple of 6 below
 * 256) so the modulo is uniform.
 */
function drawDie(seed: Uint8Array, label: number): number {
  for (let counter = 0; counter < 1 << 20; counter++) {
    const mac = hmac(nobleSha256, seed, concatBytes(u32be(label), u32be(counter)));
    for (const b of mac) {
      if (b < 252) return (b % 6) + 1;
    }
  }
  /* c8 ignore next */ throw new Error('beacon: exhausted PRF (statistically impossible)');
}

/**
 * Resolve a roll from the available reveals. `reveals` should be the verified
 * reveals (callers verify against commitments first); a committed seat that
 * failed to reveal is simply absent — the timeout default — and the roll still
 * stands as long as at least one honest reveal is present.
 */
export function roll(reveals: readonly PartyReveal[], turnIndex: number, prevBeacon: Uint8Array = ZERO_BEACON): BeaconResult {
  if (reveals.length === 0) throw new Error('beacon: need at least one reveal');
  const seed = beaconSeed(reveals, turnIndex, prevBeacon);
  const d1 = drawDie(seed, 0);
  const d2 = drawDie(seed, 1);
  return {
    dice: [d1, d2],
    total: d1 + d2,
    beacon: seed,
    contributors: [...reveals].map((r) => r.seat).sort((a, b) => a - b),
  };
}

export interface RollEntryInput {
  readonly commits: readonly { seat: number; c: Uint8Array }[];
  readonly reveals: readonly { seat: number; secret: Uint8Array }[];
  readonly liveSeats: readonly number[];  // eligible (non-bankrupt) seats this turn
  readonly turnIndex: number;
  readonly prevBeacon: Uint8Array;
  readonly claimedDice?: readonly [number, number];
}
export interface RollEntryResult { readonly ok: boolean; readonly reason: string; readonly dice?: readonly [number, number]; readonly beacon?: Uint8Array }

/**
 * THE single roll verifier (shared by @estates/audit AND @estates/net, audit #4):
 * one commitment per live seat, no duplicate commit/reveal, no non-live reveal,
 * each reveal opens its prior commitment, ≥1 honest reveal, and the dice derived
 * ONLY from the canonical commitment-verified reveal set (matching any claim).
 */
export function verifyRollEntry(inp: RollEntryInput): RollEntryResult {
  const live = new Set(inp.liveSeats);
  const cSeats = inp.commits.map((c) => c.seat);
  if (new Set(cSeats).size !== cSeats.length) return { ok: false, reason: 'duplicate commitment seat' };
  for (const c of inp.commits) if (!live.has(c.seat)) return { ok: false, reason: `commitment from a non-live seat ${c.seat}` };
  const cmap = new Map<number, Uint8Array>(inp.commits.map((c) => [c.seat, c.c]));
  const rSeats = inp.reveals.map((r) => r.seat);
  if (new Set(rSeats).size !== rSeats.length) return { ok: false, reason: 'duplicate reveal seat' };
  const reveals: PartyReveal[] = [];
  for (const rv of inp.reveals) {
    if (!live.has(rv.seat)) return { ok: false, reason: `reveal from a non-live / non-seat ${rv.seat}` };
    const c = cmap.get(rv.seat);
    if (!c) return { ok: false, reason: `reveal from seat ${rv.seat} with no prior commitment` };
    if (!verifyReveal(rv.secret, c)) return { ok: false, reason: `reveal from seat ${rv.seat} does not open its commitment` };
    reveals.push({ seat: rv.seat, secret: rv.secret });
  }
  if (reveals.length === 0) return { ok: false, reason: 'no honest reveal (beacon unbiasable condition fails)' };
  const br = roll(reveals, inp.turnIndex, inp.prevBeacon);
  if (inp.claimedDice && (br.dice[0] !== inp.claimedDice[0] || br.dice[1] !== inp.claimedDice[1])) {
    return { ok: false, reason: `dice ${inp.claimedDice} do not match the beacon (recomputed ${br.dice})` };
  }
  return { ok: true, reason: 'roll verified', dice: br.dice, beacon: br.beacon };
}

/**
 * Verify a set of (seat, secret, commitment) and return only the reveals whose
 * secret matches its commitment — the honest set used to roll (timeout default
 * drops the rest).
 */
export function honestReveals(
  entries: readonly { seat: number; secret: Uint8Array; commitment: Uint8Array }[],
): PartyReveal[] {
  return entries.filter((e) => verifyReveal(e.secret, e.commitment)).map((e) => ({ seat: e.seat, secret: e.secret }));
}
