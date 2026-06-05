# @estates/spv — security boundary

Reference cryptographic infrastructure: **native SPV inclusion** (C3). A light client
proves a transaction is in a block by RECOMPUTING the Merkle root from a partial branch
and checking it against the block header's `merkleRoot` (committed under proof-of-work).
No trusted full node, no third-party REST. Written so an auditor can attack it.

## What this package is

- `merkleRoot`/`buildProof` — compute a root / an inclusion branch (proof-serving / tests).
- `rootFromProof`/`verifyInclusion`/`verifyAgainstHeader` — recompute the root implied by a
  `txid` + branch and compare it to a trusted `merkleRoot` (the inclusion backbone behind
  BEEF/BUMP). The transport only SUPPLIES proofs — it is never trusted to assert them.
- `serializeHeader`/`blockHash` — the 80-byte header whose `merkleRoot` is the trust anchor.

## Threat model

The `proof` (index + branch) is **untrusted**: a forged/wrong/over-long branch, a wrong
index, mismatched-length sibling hashes. The verifier must return `false` on any of these
— never throw, never accept a forgery.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `rootFromProof(txid, proof)` | **Untrusted proof** | Pure hash chain over `proof.branch`; the branch length is bounded by the upstream parser (`@estates/merkleblock` caps the tree at `2^25` leaves → ≤ 25 siblings). Mismatched-length hashes just produce a non-matching root. |
| `verifyInclusion(txid, proof, expectedRoot)` | **Untrusted proof** | `bytesEqual(rootFromProof(...), expectedRoot)`; `bytesEqual` returns `false` on any length/content mismatch — never throws. A forged proof fails. |
| `verifyAgainstHeader(txid, proof, header)` | **Untrusted proof** | Binds inclusion to a specific, PoW-checkable header's `merkleRoot`. |
| `serializeHeader` | **Semi-trusted** | Throws if `prevHash`/`merkleRoot` are not 32 bytes (our own header construction). |

## Invariants (each is a test — see INVARIANTS.md)

- **Soundness:** a valid branch recomputes the header's root; a forged/wrong/short branch
  does not — `verifyInclusion` returns `false`, never throws.
- **Trust anchor:** inclusion is only ever accepted against a caller-supplied
  `merkleRoot`/header, never on a supplier's assertion.

## What must never be assumed

- That the proof supplier is honest — only the recomputed-root math is trusted.
- That `proof.branch` hashes are 32 bytes — a mismatch fails the comparison, not throws.

## Known non-goals

- Header proof-of-work / chain selection (the header is the trust anchor passed in; the
  header-chain layer validates PoW).
- Parsing raw proof bytes — that is `@estates/merkleblock`/`@estates/node` (bounded there).
