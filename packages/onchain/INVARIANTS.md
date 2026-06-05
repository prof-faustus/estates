# @estates/onchain — invariants (every claim is an executable test)

Tests live in `packages/onchain/test/onchain.test.ts`. Read a claim, find the test,
try to break it.

## NFT encoding & shape

| # | Claim | Test |
|---|---|---|
| E1 | Title state encodes and decodes round-trip (incl. build + mortgage) | "title state encodes and decodes round-trip (incl. build + mortgage)" |
| E2 | A Reprieve NFT round-trips with kind REPRIEVE | "Reprieve NFT round-trips with kind REPRIEVE" |
| E3 | Every NFT is a 1-sat NFT; the locking script is `<state> OP_DROP <P2PKH>`, no OP_RETURN | "every NFT is a 1-sat NFT; the locking script is <state> OP_DROP <P2PKH>, no OP_RETURN" |

## No data-carrier opcode

| # | Claim | Test |
|---|---|---|
| D1 | `serializeScript` THROWS on OP_RETURN (defence in depth) | "serializeScript THROWS on OP_RETURN (defence in depth)" |

## Transfer / re-mint

| # | Claim | Test |
|---|---|---|
| T1 | Transfer re-mints to a new owner (same state, different predicate) | "transfer re-mints to a new owner (same state, different predicate)" |
| T2 | A build / mortgage re-mint changes the state blob (and thus the script) | "build / mortgage re-mint changes the state blob (and thus the script)" |

## Provenance & validation (no silent masking)

| # | Claim | Test |
|---|---|---|
| V1 | A forged title fails provenance when the genesis outpoint does not match | "forged title: provenance fails when the genesis outpoint does not match" |
| V2 | Malformed state pushdata is rejected on decode | "malformed state pushdata is rejected on decode" |
| V3 | `encodeTitleState` rejects out-of-range / non-canonical state (no silent masking) | "encodeTitleState rejects out-of-range / non-canonical state (no silent masking)" |
| V4 | `decodeTitleState` rejects a non-canonical mortgaged byte and impossible fields | "decodeTitleState rejects a non-canonical mortgaged byte and impossible fields" |
| V5 | `validateTitleState` accepts every legal title and a canonical REPRIEVE | "validateTitleState accepts every legal title and a canonical REPRIEVE" |
| V6 | Game tags are domain-separated by kind | "game tags are domain-separated by kind" |

## Native-sat payments

| # | Claim | Test |
|---|---|---|
| P1 | A native-sat payment is an ordinary P2PKH output; negative amounts rejected | "native-sat payment is an ordinary P2PKH output; negative amounts rejected" |
| P2 | `p2pkh` requires a 20-byte HASH160 | "p2pkh requires a 20-byte HASH160" |
