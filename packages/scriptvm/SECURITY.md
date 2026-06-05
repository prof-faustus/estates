# @estates/scriptvm — security boundary

Reference cryptographic infrastructure: a **BSV Script interpreter** that proves an input
SATISFIES its prevout — real BIP-143 sighash + ECDSA `OP_CHECKSIG` on a stack machine,
banned-opcode enforcement, and fee/value conservation. "Serialization is not validation":
this is the executable spend-validity check the replay/audit and wallet rely on. Written
so an auditor can attack it.

## What this package is

`verifyInput(tx, i, prevout)` parses the unlocking + locking scripts, runs them on a
stack with `OP_CHECKSIG` computing a real BIP-143 sighash, and returns whether the input
satisfies the prevout. `verifyTx(tx, prevouts)` checks every input, rejects a banned
opcode in any output, and enforces a non-negative fee. It covers exactly the ESTATES
script forms: P2PKH, the `<state> OP_DROP <P2PKH>` NFT/commit output, and the
`<rh> <tag> OP_2DROP OP_TRUE` bank covenant.

## Threat model

The `scriptSig` (and, when verifying an attacker-supplied tx, the prevout `script`) are
**untrusted bytes**. An attacker will try:

- truncated pushes / `OP_PUSHDATA1`/`OP_PUSHDATA2` claiming more bytes than present;
- a `scriptSig` that is not push-only (smuggling opcodes into the unlocking script);
- a banned opcode (`OP_RETURN`, etc.) in a script or output;
- a malformed DER signature, an off-curve / wrong-length pubkey, a too-short sig;
- a forged signature, a signature over a different prevout value or different outputs
  (BIP-143 must bind both);
- value games: outputs exceeding inputs (negative fee).

**No exception may escape `verifyInput`/`verifyTx`, and execution must always terminate**
(the supported opcode set has no loops; work is bounded by script length).

## Trust boundary

| Surface | Trust | Contract |
|---|---|---|
| `verifyInput(tx, i, prevout)` | **Untrusted scripts** | Total: parses both scripts and runs them inside `try/catch`; any parse/exec failure (truncated push, non-push scriptSig, banned op, underflow, bad DER, false top-of-stack) is a clean `{ok:false}`. Never throws. |
| `verifyTx(tx, prevouts)` | **Untrusted scripts/values** | Total: requires `prevouts.length == inputs.length`, rejects a banned opcode in any output, rejects a negative fee, then `verifyInput`s each input. Never throws. |
| `parseScript(script)` | **Untrusted** | Throws by contract on a truncated push — only ever called inside the guarded boundary, which converts the throw to `{ok:false}`. |
| `sighash`, `derToCompact`, `compactToDer` | helpers | Pure; `derToCompact` throws on bad DER, caught at the `OP_CHECKSIG` site (→ signature invalid). |

## Cryptographic invariants

- `OP_CHECKSIG` recomputes the **BIP-143** sighash over the real preimage (version,
  hashPrevouts, hashSequence, outpoint, scriptCode, **prevout value**, sequence,
  hashOutputs, locktime, hashType) — so a signature is bound to the exact prevout value
  and the exact outputs. Changing either invalidates it.
- @noble/secp256k1 v2 is compact-only; DER from the scriptSig is converted before verify,
  and any malformed DER / bad point makes the check fail (not throw).

## Invariants (each is a test — see INVARIANTS.md)

- **Satisfaction:** a real ECDSA-signed P2PKH input satisfies its prevout; the covenant
  `OP_TRUE` output is spendable.
- **Authenticity:** a wrong-key/tampered signature, or a signature over a different
  amount, fails.
- **Policy:** a banned opcode in an output and a negative fee are rejected.
- **Totality / DoS:** hostile scripts (truncated pushes, non-push scriptSig, banned ops,
  bad DER) and 50k random scriptSig/prevout pairs never make the boundary throw or hang.

## What must never be assumed

- That a `scriptSig` is push-only or well-formed — re-checked; non-push is rejected.
- That a DER signature or pubkey is valid — a bad one fails the check, never throws.
- That a signature is honest because it parses — it must satisfy the BIP-143 sighash
  bound to the prevout value and the outputs.

## Known non-goals

- A full BSV opcode set — only the opcodes the ESTATES script forms use are implemented;
  any other opcode is rejected (`unsupported opcode`), which is intentional fail-closed
  behaviour for this reference, not a general-purpose VM.
- The covenant's *payout predicate* (who may spend the bank reserve, and to where) is
  enforced by `@estates/bank`'s `verifyCovenantSpend`, not by the `OP_TRUE` script here.
