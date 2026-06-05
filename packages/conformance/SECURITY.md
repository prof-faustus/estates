# @estates/conformance — security boundary

Reference infrastructure: the **legality source-of-truth vectors** + canonical state
hashing. Written so an auditor can attack it.

## What this package is

A vector is one `(state, action) → expected` pair, where `expected` is either the
**canonical hash** of the resulting state or a typed rejection code. `hashState`
computes the canonical hash by serializing the state **minus the advisory `log`** with
lexicographically sorted keys, so two implementations that agree on the rules produce
byte-identical hashes.

This is the contract that pins **every** implementation to one behaviour: the web
engine, and the native `Estates.Core` (which re-derives these hashes in C# and asserts
equality). A rules divergence in any implementation fails against these vectors.

## The properties this exists to guarantee

> 1. There is a single canonical hash for any game state (deterministic, key-sorted,
>    log-excluded).
> 2. The vector file is the shared legality contract every engine must satisfy.

- **Canonical hashing:** key order is fixed (lexicographic), the advisory `log` is
  excluded, and the encoding matches across Node and C# — this is what makes the
  native exe provably equal to the web (see `apps/native` conformance layers).
- **Versioned, non-trivial vectors:** the vector file is present, versioned to the
  params SoT, and non-trivial; a stale or empty contract is rejected.

## Threat model

- Two implementations silently diverge on a rule → impossible to hide: the canonical
  hash differs and the vector check fails.
- The `log` (advisory text) is smuggled into consensus → excluded from the hash by
  construction.
- A stale/empty vector file passes as a contract → rejected (present + versioned +
  non-trivial).

## What this package does NOT do

- It does not implement the rules (`@estates/engine` does) — it defines the canonical
  hash and the vector format the rules are checked against.
