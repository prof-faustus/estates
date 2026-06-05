# @estates/sidecar — invariants (every claim is an executable test)

Tests live in `packages/sidecar/test/sidecar.test.ts`. Read a claim, find the test, try
to break it.

## Protocol authority & authenticity

| # | Claim | Test |
|---|---|---|
| A1 | A forged-signature move is dropped (socket delivery ≠ authentication) | "a badly-SIGNED move is rejected" |
| A2 | A signed move is authored by the player's own non-custodial key, chat is addressed by it | "moves are signed by the PLAYER key, and chat is addressed by it" |

## Validity ≠ signature (the decode boundary)

| # | Claim | Test |
|---|---|---|
| D1 | `decodeFrame` accepts well-formed bc/br/move/chat; rejects hostile shapes (non-JSON, unknown `t`, out-of-range turn/dice, bad sig length, malformed beacon, non-hex/oversized pkhs) | "decodeFrame accepts well-formed bc/br/move/chat and rejects hostile shapes" |
| D2 | `isAction` rejects unknown / prototype-pollution action types | same test + "decodeFrame is FUZZ-PROOF" (asserts `isAction({type:'__proto__'}) === false`) |

## Beacon dice & manifest binding (authority)

| # | Claim | Test |
|---|---|---|
| B1 | A signed `ROLL` with mover-CHOSEN dice (dice ≠ beacon of revealed secrets) is rejected | "a signed ROLL with MOVER-CHOSEN dice (not the beacon) is REJECTED (#2)" |
| B2 | The signed payload BINDS the output-key manifest; an on-wire pkhs that differs from the signed manifest is rejected | "the signed payload BINDS the output-key manifest — a tampered pkhs is rejected (#3)" |

## Totality / DoS resistance

| # | Claim | Test |
|---|---|---|
| V1 | A live peer never crashes and never advances/corrupts state on a barrage of hostile frames | "a HOSTILE move frame never crashes a live peer / never advances state" |
| V2 | `decodeFrame` survives 100k random byte frames with no throw and in bounded time | "decodeFrame is FUZZ-PROOF: 100k random frames never throw or hang" |

## Determinism (consensus)

| # | Claim | Test |
|---|---|---|
| L1 | Both peers replay the SAME beacon-diced state byte-for-byte; no sats are minted | "a full BEACON-diced game over real sockets converges byte-for-byte" |

## How to attack this package (auditor guide)

1. Send `{t:'move', action:{type:'EVIL'}, sig:…}` with ANY signature → must be ignored
   by `decodeFrame` (D1). A state change from a non-Action is a finding.
2. Send `{t:'move', action:{type:'ROLL', dice:[9,9]}, …}` → out-of-range dice rejected
   at decode (D1). Send in-range chosen dice with a self-consistent beacon → rejected
   because `dice ≠ beacon(secrets)` (B1).
3. Sign a payload committing to `pkhs {0: aa…}` but put `{0: bb…}` on the wire → rejected
   (B2). The output-key swap must not spend to your address.
4. Send a `pkhs` map with 999 entries, or a `beacon` with non-hex fields, or a 1e12 turn
   → all rejected without allocation or throw (D1/V1).
5. Fuzz the socket with arbitrary bytes (V1/V2). Any throw / hang / forged or advanced
   state is a finding.
