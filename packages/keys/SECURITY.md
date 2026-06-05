# @estates/keys — security boundary

Reference cryptographic infrastructure: **deterministic, indexed, ONE-USE** key
derivation (BSV BRC-42). Written so an auditor can attack it.

## What this package is

No address is ever reused. Every spend key is derived **once**, deterministically,
from a master key + an indexed "invoice number", via ECDH-tweak derivation:

```
shared    S = ECDH(myPriv, theirPub)            (symmetric: ECDH(a,B) = ECDH(b,A))
tweak     t = HMAC-SHA256(S.x, invoiceNumber) mod n
childPriv = (theirPriv + t) mod n               (recipient derives the secret)
childPub  = recipientPub + t·G                  (sender derives the same pubkey)
```

Two modes:
- **Self ("Alice only"):** derive against her own pubkey (`S = ECDH(a, A)`), indexed
  `self/<i>` — a deterministic hash chain of one-use keys only she can produce.
- **Pay ("Alice → Bob"):** Alice derives Bob's one-use child **pubkey** to pay him;
  Bob derives the matching child **privkey** to spend. Neither reuses a key, and the
  child is unlinkable to Bob's identity key without the shared secret.

`spendContext(...)` is the canonical invoice: it binds a key to exactly one on-chain
purpose — `gameId, network, version, purpose, role/seat, asset, turnIndex,
outputIndex` — so the same master never produces the same key for two outputs.

## The properties this exists to guarantee

> 1. Every key is fresh and one-use (no address reuse, ever).
> 2. A payment to a derived pubkey is always recoverable by — and only by — the
>    intended recipient.
> 3. The derivation is unlinkable to the recipient's identity without the shared secret.

- **Recoverability:** payer and recipient build the **identical** `spendContext`, so
  the recipient can always derive the private key for an output addressed to them
  (symmetry of ECDH).
- **One-use:** any change to purpose/role/turn/output yields a different key; the
  `self/<i>` chain issues a distinct key each `next()`.
- **Outsider exclusion:** a party with the wrong counterparty key cannot derive the
  shared secret, hence cannot derive the child key.

## Threat model

- An outsider (wrong counterparty pubkey) tries to derive the same child key →
  cannot (no shared secret).
- A caller reuses a context to get the "same" key for two outputs → contexts differ
  by `outputIndex`/`turn`/`purpose`, so keys differ — reuse is structurally avoided.
- A derived scalar that is 0 or ≥ n (invalid) → rejected; derived keys are valid
  secp256k1 scalars.
- Linking a one-use child back to the recipient's identity key without the shared
  secret → infeasible.

## What this package does NOT do

- It does not store or transmit keys; it derives them. Master-key custody is the
  wallet's concern (`@estates/wallet`).
- It does not sign transactions (`@estates/trade` / `@estates/scriptvm` do); it only
  produces the key material an output is locked to / spent with.
