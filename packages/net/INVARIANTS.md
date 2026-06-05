# @estates/net — invariants (every claim is an executable test)

Tests live in `packages/net/test/net.test.ts`. Read a claim, find the test, try to break
it.

## Deterministic replay (consensus)

| # | Claim | Test |
|---|---|---|
| R1 | Every peer replays the SAME state from the SAME ordered transcript | the determinism/convergence tests over a recorded game |
| R2 | The relay is opaque: it stores/fans out bytes and never interprets them | "the relay is opaque: it stores/fans out bytes and never interprets them" |
| R3 | A roll is applied only from a verified commit→reveal transcript (same verifier as audit) | roll-verification tests + the convergence test |

## Validity ≠ delivery (the decode boundary)

| # | Claim | Test |
|---|---|---|
| D1 | `decodeEnvelope` accepts a valid envelope and rejects hostile payloads (non-JSON, scalar, bad seq, unknown kind, bad/unknown action, non-array/non-hex/oversized roll) | "decodeEnvelope accepts a valid envelope and rejects hostile payloads" |

## Totality / DoS resistance

| # | Claim | Test |
|---|---|---|
| V1 | A hostile relay payload never crashes `ingest` and never advances state | "a HOSTILE relay payload never crashes ingest and never advances state" |
| V2 | A hostile payload / throwing subscriber never breaks delivery to honest peers | "a hostile relay payload in the fan-out never breaks delivery to honest peers" |
| V3 | `decodeEnvelope` survives 100k random payloads with no throw/hang | "decodeEnvelope is FUZZ-PROOF: 100k random payloads never throw or hang" |

## How to attack this package (auditor guide)

1. Publish a payload that is `null`, `42`, or `{ not json` → `decodeEnvelope` returns
   `null`, `ingest` returns false, no state change, no throw (D1/V1).
2. Publish `{seq:0, entry:{kind:'roll', commits:[{seat:0,c:'zz'}], reveals:[], dice:[1,1]}}`
   — the `c` is non-hex that would throw inside `fromHex`. Must be rejected at decode,
   before `fromHex` runs (D1). A throw here is a finding.
3. Publish a roll with a 99-entry `commits` list, or `seq: 1e12` → rejected without
   allocation (D1).
4. Publish `{entry:{kind:'action', action:{type:'__proto__'}}}` or any non-Action →
   ignored; a state change is a finding (D1/V1).
5. Subscribe a callback that throws, then publish → other subscribers still receive the
   message; the publisher does not throw (V2).
6. Fuzz with 100k random byte payloads (V3). Any throw/hang is a finding.
