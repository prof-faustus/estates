# @estates/txmap — security boundary

Reference cryptographic infrastructure: **every move is its own on-chain BSV
transaction**, and `decodeActionCommit` reads an on-chain action-commitment blob back
into the move it records. That blob is untrusted bytes (read from the chain via a
possibly-hostile relay/node), so its decoder is the boundary. Written so an auditor can
attack it.

## What this package is

`encodeActionCommit(action, turnIndex, actor)` produces the canonical pushdata
commitment `tag ‖ turnIndex ‖ actor ‖ code ‖ params` that `commitOutput` writes as a
1-sat `<commit> OP_DROP <P2PKH>` output. `decodeActionCommit(blob)` is the inverse — the
auditor's read-back, used by `@estates/replay` to reconstruct and re-verify a whole game
from chain alone.

## Threat model

The commitment blob is **untrusted**. An attacker may publish on-chain (or a hostile
relay may hand back) a blob that:

- lacks the tag, or is truncated mid-header / mid-params;
- carries an unknown action code, or an out-of-range `actor`/`propertyId`/`seat`;
- carries out-of-range `ROLL` dice;
- carries trailing garbage after a valid move (parser ambiguity);
- is otherwise malformed such that a lax decoder would read `undefined` into a field and
  yield a **malformed `Action`** that then flows into the engine.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `decodeActionCommit(blob)` | **Fully untrusted bytes** | **Strict.** Throws by contract on ANY malformed blob — its consumer (`@estates/replay`) wraps it and treats a throw as "reject this move". Every read is length-checked; every field is range-validated (`actor`/`seat` ≤ 7, `propertyId` ≤ 39, `dice` ∈ 1..6, `PAY_TAX` choice ∈ {0,1}); the blob must be EXACTLY the expected length (no truncation, no trailing garbage). So a tagged-but-garbage blob can never produce a malformed `Action`. |
| `encodeActionCommit`, `commitOutput`, `txForAction` | **Trusted** (our own outbound) | Build the canonical commitment / transaction. |

## Why "throws" instead of "returns null" here

`decodeActionCommit`'s sole consumer, `@estates/replay`, already wraps every call in
`try/catch` and converts a throw into a clean `{ok:false, reason}` for that move. Keeping
the throw-on-malformed contract (a) matches that consumer, (b) keeps the auditable
"reason" string precise, and (c) preserves the existing public API. The hardening is that
the throw is now **exhaustive** — no malformed blob slips through as a bad `Action`.

## Invariants (each is a test — see INVARIANTS.md)

- **Round-trip:** every action type encodes and decodes back to itself.
- **Strict reject:** a tagged-but-garbage / truncated / out-of-range / trailing-garbage
  blob throws — never yields a malformed `Action`.
- **Fuzz-proof:** 50k random (and tagged-random) blobs only ever throw or decode to a
  well-formed move; never hang.

## What must never be assumed

- That a blob with the right tag has well-formed or in-range fields — all re-validated.
- That the blob is the right length — exact-length is enforced (no truncation/trailing).

## Known non-goals

- Authenticity of the move (that the actor was entitled to make it) — that is enforced by
  the signature layer (`@estates/table`/`sidecar`) and the engine; here we only decode
  the recorded action faithfully and strictly.
