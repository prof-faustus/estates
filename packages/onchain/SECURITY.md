# @estates/onchain — security boundary

Reference cryptographic infrastructure: the **1-sat NFT** encoding + native-sat
payments — the on-chain representation every higher layer builds on. Written so an
auditor can attack it.

## What this package is

- **NFT (title deed / Reprieve card):** a 1-satoshi UTXO whose locking script is
  `<state> OP_DROP <P2PKH(owner)>` — the object's state is fixed-layout pushdata
  (73 bytes: kind, 32-byte gameTag, propertyId, groupId, buildLevel, mortgaged,
  32-byte genesis outpoint, vout) consumed by `OP_DROP`/`OP_2DROP`, followed by a
  standard P2PKH ownership predicate. Ownership transfers by **spending** the 1-sat
  output into a new 1-sat output with the new owner.
- **Money:** native satoshis as ordinary P2PKH outputs — never a token.

## The properties this exists to guarantee

> 1. State is committed in the live script and cannot be silently malformed.
> 2. No data-carrier opcode is ever emitted (`OP_RETURN` is rejected by construction).
> 3. An NFT's provenance is pinned to its genesis outpoint.

- **Canonical state:** `encodeTitleState`/`validateTitleState` reject out-of-range or
  non-canonical fields (bad propertyId/groupId/buildLevel, a non-`{0,1}` mortgaged
  byte, an impossible vout, a non-canonical REPRIEVE) with **no silent masking** —
  a malformed/adversarial title can never encode, and `decodeTitleState` rejects
  malformed pushdata. The layout is fixed-length, so decoding never reads past the
  buffer.
- **No OP_RETURN:** `serializeScript` **throws** if a script contains `OP_RETURN`
  (defence in depth); state lives in spendable pushdata, not a data output.
- **Provenance:** the state carries the 32-byte genesis outpoint; a forged title
  whose genesis does not match fails provenance.
- **Domain-separated game binding:** `gameTag` is domain-separated by kind, so a
  TITLE tag and a REPRIEVE tag for the same game differ.

## Threat model

- An adversary crafts a title with out-of-range ids/levels or a non-canonical
  mortgaged byte → rejected on encode and decode (no silent masking).
- An attacker tries to slip an `OP_RETURN` data output → `serializeScript` throws.
- A forged title claims a genesis outpoint it does not descend from → provenance
  check fails.
- A negative-amount payment or a non-20-byte HASH160 → rejected.

## What this package does NOT do

- It does not verify scripts/signatures (that is `@estates/scriptvm`, BIP-143) or
  decide ownership transfer legality (that is `@estates/ledger` true-move + the
  engine). It defines the canonical bytes those layers operate on.
