# ESTATES SPV — Craig's SPV (IP-to-IP envelopes + Bloom), reference

ESTATES does **not** use BTC-style SPV (download all headers, query a server, scan the chain). It uses the
original SPV model: a payment carries its own proof, delivered peer-to-peer, and the receiving wallet
verifies and keeps that proof. This document specifies the envelope, verification, Bloom matching, and the
node's role as a pure proof source.

---

## 1. The SPV envelope

A coin is delivered as `SpvEnvelope(RawTx, Header80, Branch, Index)`:

- **RawTx** — the full transaction bytes that pay the recipient.
- **Header80** — the 80-byte block header of the block that mined the transaction.
- **Branch** — the merkle branch (sibling hashes) from the transaction up to the block's merkle root.
- **Index** — the transaction's position in the block (drives the left/right hashing at each level).

The **sender** stores the envelope and hands it to the payee IP-to-IP with the payment. The payee verifies
and stores it, so the payee can in turn hand it to whoever they pay next. Proofs propagate with money.

## 2. Verification (`SpvEnvelope.Verify`)

1. Parse `RawTx` → fail if malformed.
2. Parse `Header80` → fail if malformed; check **proof-of-work**: the header hash meets its stated target
   (`BsvHeaders.MeetsProofOfWork`, `CompactToTarget`). A header that doesn't meet its own difficulty is
   rejected — an attacker cannot fabricate a cheap header.
3. Recompute the merkle root from the transaction's txid + `Branch` at `Index`
   (`MerkleProof.Verify` / `MerkleProof.Root`) and require it to equal the header's merkle root.

If all three hold, the transaction was demonstrably included in a block that cost real proof-of-work. No
node is asked; the proof is self-contained.

## 3. The SPV wallet (`SpvWallet`)

Holds owned P2PKH scripts (the wallet's sub-key addresses, index ≥ 1). On `Receive(envelope)`:
verify → for each output paying an owned script, credit the coin and **store the envelope** (always).
`Balance()` sums the owned UTXOs. `ProofFor(outpoint)` returns the stored envelope to hand to the next
payee when that coin is spent (`SpvSpend` attaches input proofs to the payment). `Save`/`Load` persist the
envelopes so balance shows instantly on open with no re-fetch. `ReceivedHistory()` drives the History tab.

## 4. Spending (`SpvSpend`)

`BuildMany` selects owned UTXOs (largest-first), excluding **frozen** coins (coin control), builds the
outputs (pay-to-many + change to a sub-key), and signs each input with its one-time key using FORKID
sighash (`SIGHASH_ALL | FORKID = 0x41`), low-S ECDSA. It returns the signed tx plus the spent coins'
stored envelopes, which the payer hands to the payee so they can verify the inputs were real mined coins.

## 5. Bloom filter (BIP37) — `BloomFilter`

So a wallet can ask a serving peer for *only* the transactions that touch its addresses without revealing
the exact set, it loads a Bloom filter:

- MurmurHash3 x86_32; for hash function `i` the seed is `i * 0xFBA4C795 + nTweak`; the set bit is
  `murmur3(seed, item) mod (filterBytes * 8)`.
- Size and hash-function count are derived from the element count and the target false-positive rate
  (capped at BIP37's 36 000 bytes / 50 hash functions).
- `Insert` sets bits for an item (address/script hash, pubkey); `Contains` tests membership — **no false
  negatives**, a tunable false-positive rate.
- `FilterLoad(flags)` serialises the `filterload` wire payload:
  `varint(len) ‖ data ‖ nHashFuncs(LE32) ‖ nTweak(LE32) ‖ nFlags(1)`.

The wallet builds a filter over its watched addresses; the Network/SPV tab shows the live parameters.

## 6. The node's role — proof source only

A BSV node is contacted **only** to fetch proofs for coins paid to the wallet's own addresses (bring-up /
sync), via JSON-RPC (`getrawtransaction`, `getblock`, `getblockheader`) assembled into envelopes
(`SpvSync` → `BlockMerkle.BranchFor` → `SpvEnvelope`). RPC ports: regtest 18443, testnet 18332, mainnet
8332. In live play, peers deliver envelopes directly; there is no dependency on a node for state, and the
estate node itself never mines.

## 7. Why this model

- **Instant + offline-of-nothing:** the proof arrives with the money; the wallet never blocks on a chain
  scan or header download. (The system is always online; SPV here means "no node query for state.")
- **Trust-minimised:** proof-of-work on the header + merkle inclusion is checked locally; a peer cannot
  lie about a payment being mined.
- **Composable:** because proofs are stored and re-handed, value + its provenance flow together across the
  peer graph.

---

*Part of the exhaustive ESTATES reference documentation; grows with the code.*
