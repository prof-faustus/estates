# @estates/table — invariants (every claim is an executable test)

Tests live in `packages/table/test/table.test.ts`. Read a claim, find the test, try
to break it.

## Protocol authority & authenticity

| # | Claim | Test |
|---|---|---|
| A1 | An unsigned / forged message is dropped (relay order ≠ authentication) | "an UNSIGNED / forged table message is rejected …" |
| A2 | Lobby announcements are signed; host must equal the signer | "lobby announcements are signed; forged/unsigned announces are rejected" |
| A3 | Only the human host starts; never automatically, never a bot | "no auto-start for N: full lobby stays in lobby until the host calls start" (N=2..6) + "a separate simulated player … the human still starts" |
| A4 | Seats fill 0..N-1; non-host cannot start; start only when full | "lobby N: seats fill …; only host can start; only when full" (N=2..6) |

## Validity ≠ signature (the decode boundary)

| # | Claim | Test |
|---|---|---|
| D1 | `isAction` accepts every valid action type/fields, rejects hostile shapes | "isAction validates every action type + per-type fields; rejects hostile shapes" |
| D2 | `isEngineConfig` bounds seatCount/bankReserve, rejects hostile configs | "isEngineConfig bounds seatCount/bankReserve and rejects hostile configs (no DoS)" |
| D3 | A validly-shaped envelope with a HOSTILE config/action/seat/hex is rejected | "decodeSigned: a validly-shaped envelope with a HOSTILE config/action/seat is rejected" |
| D4 | Bad meta (non-hex/short signPub or sig, missing fields, non-JSON) is rejected | "decodeSigned: bad meta … is rejected" |

## Totality / DoS resistance

| # | Claim | Test |
|---|---|---|
| V1 | `rebuild` never throws and never forges table/seat/state on hostile frames | "rebuild is FAIL-CLOSED: hostile frames never throw, never forge table/seat/state" |
| V2 | `decodeSigned` survives 100k random frames with no throw/hang | "rebuild decoder is FUZZ-PROOF: 100k random frames never throw decodeSigned" |

## Determinism (consensus)

| # | Claim | Test |
|---|---|---|
| L1 | Every peer replays the SAME state from the SAME ordered log | "determinism: every peer replays the SAME beacon-diced state" + every "full N-human game stays in lockstep …" |
| L2 | A separate auto-play peer drives its OWN seat in lockstep | "a separate simulated player … plays only its own seat" |

## How to attack this package (auditor guide)

1. Publish a `start` with a **valid signature** but `config.seatCount = 1e9` → must
   NOT call `initialState` (no 1e9-seat allocation). If the client hangs/OOMs, that
   is a DoS finding (D2/D3).
2. Publish `{kind:'action', action:{type:'__proto__'}}` or any non-Action → ignored
   (D1/D3). A state change from a non-Action is a finding.
3. Sign a `seat` claim for seat 0 with key K while another seat is already held by K
   → must be rejected (one key, one seat).
4. Replay another peer's `seat` frame from your own connection → the embedded `who`
   must equal the signer, so you cannot claim their seat (A1 + seat rule).
5. Fuzz the relay with arbitrary bytes (V1/V2). Any throw / hang / forged table or
   seat is a finding.
