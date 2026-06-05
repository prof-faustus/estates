# @estates/deck — security boundary

Reference cryptographic infrastructure: **mental-poker concealed cards** — every property
and Fate/Treasury card is an encrypted, table-bound, individually-keyed 1-sat NFT, dealt
via a dealerless shuffle so no single party knows the order. The holder-side opener and
the transcript verifier are the trust boundaries. Written so an auditor can attack it.

## What this package is

- `sealTo`/`open` — ECIES (ephemeral ECDH + AES-256-GCM) seal/open of a card face.
- `commit`/`verifyReveal` — a binding+hiding commitment `H(face ‖ blind)` so a card's
  identity is fixed before reveal and cannot be swapped.
- `encodeFace`/`decodeFace` — canonical, length-prefixed face encoding (so commitments are
  deterministic).
- `mintCard`/`openCard`/`transferCard` — a concealed card NFT with its OWN one-use key,
  table-bound, sealed to the current holder.
- `commitEntropy`/`combineSeed`/`permutation` — the dealerless shuffle (rejection-sampled,
  unbiased for every ESTATES set size).
- `verifyCardTranscript` — enforces one-use keys (no reuse) + table binding.

## Threat model

The card data a holder opens may come from a **malicious minter / dealer / peer**:

- a face sealed to the holder whose commitment matches but whose bytes are **malformed**
  (so a lax `decodeFace` would throw out of `openCard`);
- a card bound to a different table (worthless-elsewhere binding must hold);
- a tampered ciphertext, or a seal to the wrong key (AEAD must reject);
- a transcript that reuses a "one-use" key, or carries an off-curve `cardPub`.

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `open(priv, env)` | **Untrusted** | Returns plaintext or `null`; AEAD/parse failure → `null`, never throws. |
| `openCard(card, priv, blind, tableId)` | **Untrusted (possibly malicious minter)** | Total: returns the face or `null`. Checks table binding, opens the seal, verifies the commitment, and **decodes the face inside a guard** — a face that does not decode (a minter who committed to garbage) yields `null`, never a throw. |
| `decodeFace(b)` | **Untrusted** | Throws by contract on a malformed face (length-guarded: never reads past the buffer). Callers handling untrusted faces (`openCard`) catch it. |
| `verifyCardTranscript(cards, tableId)` | **Untrusted** | Total: rejects a non-32-byte table id, a `cardPub` that is not a 33-byte on-curve point, any reused key, or a wrong-table card — returns a result, never throws. |
| `verifyReveal`/`verifyEntropy` | **Untrusted** | Constant-length-compare; return boolean, never throw. |

## Invariants (each is a test — see INVARIANTS.md)

- **Concealment + binding:** a sealed face opens only for the holder; the commitment
  prevents a face swap; a card is worthless at another table.
- **One-use keys:** `verifyCardTranscript` rejects any reused `cardPub` and any off-curve
  key — the one-use promise is enforced, not just claimed.
- **Totality:** a malicious minter who committed to a malformed face makes `openCard`
  return `null`, never throw; 20k random sealed faces never make `openCard` throw.

## What must never be assumed

- That a face whose commitment matches is well-formed — `openCard` decodes it defensively.
- That a `cardPub` is a valid point or unique — `verifyCardTranscript` re-checks both.
- That a card belongs to this table — the table id is bound and re-checked.

## Known non-goals

- Hiding which *encrypted* card NFT a holder possesses on-chain (the concealment hides the
  card's identity/face, not the existence of the 1-sat output).
- Protecting against a holder who voluntarily reveals their own blind/face.
