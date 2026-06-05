# @estates/tx — security boundary

Reference cryptographic infrastructure. This document exists so an auditor or
attacker can find a flaw quickly. If anything here is wrong, it is a vulnerability —
report it.

## What this package is

Canonical BSV transaction **serialization** (`serializeTx`), **txid** derivation
(`txid` / `txHex`), and a **fail-closed deserializer** (`deserializeTx`). The
serialized bytes are consensus-critical: they are exactly what is double-SHA-256'd
to produce the txid an SPV proof references and the outpoint the next move spends.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `serializeTx(tx)`, `txid(tx)`, `txHex(tx)` | **Trusted input** (our own constructed `Tx`) | Throws on programmer error (e.g. `prevTxid` not 32 bytes). These are build-time bugs, never attacker-reachable, because we never serialize attacker-controlled `Tx` objects. |
| `deserializeTx(bytes)` | **Fully untrusted** (hostile peer / disk / network bytes) | MUST be total: never throws, never hangs, never reads out of bounds, never allocates beyond the input. Returns `Tx \| null`. `null` = rejected. |

## `deserializeTx` — explicit guarantees (each is a test; see INVARIANTS.md)

- **No out-of-bounds read.** A bounded `Reader` checks every read against the
  buffer length; an over-read sets `failed` and returns a zero value. It cannot
  read past the end.
- **No DoS via counts.** `nIn`/`nOut` are attacker-controlled varints. They are
  bounded by the *minimum bytes each element needs* (`nIn ≤ rem/41`,
  `nOut ≤ rem/9`) before any loop runs, so a giant count cannot drive a long loop
  or a huge allocation.
- **No DoS via lengths.** Every script length is bounded by the remaining bytes
  before the slice is taken.
- **No silent precision loss.** 8-byte values/varints above `MAX_SAFE_INTEGER` are
  rejected (would otherwise lose precision as a JS number).
- **Canonical only.** Non-canonical varint encodings are rejected, and **trailing
  bytes are rejected** — there is exactly one byte string per `Tx`.
- **Absolute cap.** Inputs `< 10` or `> 256 MiB` are rejected outright.
- **Total function.** Proven by a fuzz suite: 100k+ random + adversarial inputs,
  zero throws, zero hangs (<500 ms each); anything accepted re-serializes
  byte-for-byte.

## What must never be assumed

- That bytes given to `deserializeTx` came from `serializeTx`.
- That a declared count or length fits in memory or in the buffer.
- That a parsed value is canonical without the round-trip check.

## Recoverable vs fatal

- `deserializeTx`: **all** errors are recoverable → `null` (fail-closed). No throw.
- `serializeTx`/`txid`: a malformed *trusted* `Tx` throws (fatal programmer error).

## Known non-goals

- Script semantics / spend validity (that is `@estates/scriptvm`).
- SegWit / non-BSV features. ESTATES txs are legacy BSV (no witness).
