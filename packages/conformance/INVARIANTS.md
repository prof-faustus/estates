# @estates/conformance — invariants (every claim is an executable test)

Tests live in `packages/conformance/test/conformance.test.ts`. Read a claim, find
the test, try to break it.

## Vector contract

| # | Claim | Test |
|---|---|---|
| C1 | The vector file is present, versioned, and non-trivial | "vector file is present, versioned, and non-trivial" |

## Notes

- `hashState` excludes the advisory `log` and sorts keys, so the canonical hash is
  deterministic across implementations. The cross-implementation agreement is
  additionally proven by the native parity suite (`apps/native/Estates.Conformance`),
  which re-derives these hashes in C# and asserts byte-for-byte equality on engine,
  full-game replay, and the dealerless deck-shuffle replay.
