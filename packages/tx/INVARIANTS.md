# @estates/tx — invariants (every claim is an executable test)

Each invariant below is a security claim with the test(s) that prove it. An auditor
should be able to read a claim, find the test, and try to break it. Tests live in
`packages/tx/test/tx.test.ts`.

## Serialization / txid

| # | Claim | Positive test | Negative / hostile test |
|---|---|---|---|
| T1 | Serialization is byte-exact against a real-world vector | "serializes the genesis coinbase byte-for-byte" | — (any drift changes the vector) |
| T2 | txid = reverse(sha256(sha256(serialize))), display order | "computes the real genesis txid" | — |
| T3 | CompactSize/varint encodes at every boundary | "varint (CompactSize) boundaries" | — |
| T4 | 8-byte values serialize little-endian without f64 loss | "whole-sat values up to 8 bytes serialize little-endian" | — |
| T5 | Distinct content ⇒ distinct txid (no collision by construction) | "a 1-sat NFT-style multi-output tx is deterministic + unique per content" | — |

## Deserialization (untrusted input)

| # | Claim | Positive test | Negative / hostile test |
|---|---|---|---|
| D1 | A real tx round-trips: `serialize(deserialize(b)) === b` | "deserializeTx round-trips a real tx …" | — |
| D2 | Trailing bytes are rejected (exactly one canonical encoding) | — | "… rejects trailing garbage" (one extra byte ⇒ `null`) |
| D3 | Truncation at ANY length is rejected, never throws | — | "… rejects trailing garbage" loops every prefix `bytes.slice(0,n)` ⇒ `null` |
| D4 | Never throws on hostile input | — | "deserializeTx is FUZZ-PROOF …" (`assert.doesNotThrow` over 100k+ inputs) |
| D5 | Never hangs: bounded work regardless of declared counts | — | FUZZ-PROOF test asserts `< 500 ms` per input, incl. `2^64-1` count/length seeds |
| D6 | Anything accepted re-serializes identically (no ambiguity) | — | FUZZ-PROOF test re-serializes every accepted output and compares |
| D7 | No out-of-bounds read / over-allocation | — | covered by D4/D5 (a non-total or OOB parser would throw or hang in the fuzzer) |

## How to attack this package (auditor guide)

1. Feed `deserializeTx` a buffer whose `nIn`/`nOut` varint is `0xff…` (2^64-1) and
   see if it loops or allocates — it must return `null` immediately.
2. Feed a 1-input tx whose `scriptSig` length varint exceeds the buffer — must be
   `null`, no partial read.
3. Append one byte to a valid tx — must be `null` (D2).
4. Truncate a valid tx by one byte at every position — all must be `null` (D3).
5. Fuzz with arbitrary bytes and assert no throw/hang (D4/D5). If you can make it
   throw, hang, OOB-read, or accept a non-round-tripping input, that is a finding.
