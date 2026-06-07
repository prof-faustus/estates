// Estates.Core/SpvEnvelope.cs — BSV peer-to-peer SPV, the real model. A coin is delivered as an
// ENVELOPE: the raw transaction + its merkle proof + the block header that proves it was mined. The
// SENDER (Alice) has STORED that envelope and hands it to the payee (Bob) IP-to-IP with the payment.
// Bob's wallet VERIFIES it (merkle branch → header merkle root, and the header meets proof-of-work) and
// STORES it — ALWAYS — so Bob can in turn hand it to whoever he pays. No node query, no chain scan, no
// header IBD: the proof arrives WITH the money, so the wallet is instant and works offline.
namespace Estates.Core;

public sealed record SpvEnvelope(byte[] RawTx, byte[] Header80, IReadOnlyList<string> Branch, long Index)
{
    public string Txid() { var tx = Tx.Parse(RawTx); return tx is null ? "" : Tx.Txid(tx); }

    /// <summary>Prove the transaction was mined: the merkle proof reaches the header's merkle root AND
    /// the header itself meets its stated proof-of-work. TOTAL — false on any malformed input.</summary>
    public bool Verify()
    {
        var tx = Tx.Parse(RawTx); if (tx is null) return false;
        var hdr = BsvHeaders.Parse(Header80); if (hdr is null || !BsvHeaders.MeetsProofOfWork(hdr)) return false;
        return MerkleProof.Verify(Tx.Txid(tx), Branch, Index, hdr.MerkleRoot);
    }
}

/// <summary>An SPV wallet: it holds the coins it has RECEIVED (each with the stored envelope that proves
/// it), computes balance from its own verified UTXOs, and can produce the stored proof to hand to the
/// next payee. It never asks a node and never scans the chain.</summary>
public sealed class SpvWallet
{
    private readonly HashSet<string> _owned;                                  // owned P2PKH scripts (hex)
    private readonly Dictionary<string, (long value, byte[] script)> _utxos = new();   // outpoint -> coin
    private readonly Dictionary<string, SpvEnvelope> _proofs = new();         // outpoint -> stored proof
    private readonly object _lock = new();

    public SpvWallet(IEnumerable<byte[]> ownedScripts)
    {
        _owned = new HashSet<string>();
        foreach (var s in ownedScripts) _owned.Add(Tx.ToHex(s));
    }

    /// <summary>Receive a coin: VERIFY the envelope, then STORE it and credit any outputs paying us.
    /// Returns false (credits nothing) if the proof does not verify.</summary>
    public bool Receive(SpvEnvelope env)
    {
        if (!env.Verify()) return false;
        var tx = Tx.Parse(env.RawTx)!;
        string txid = Tx.Txid(tx);
        lock (_lock)
        {
            for (int v = 0; v < tx.Outputs.Count; v++)
                if (_owned.Contains(Tx.ToHex(tx.Outputs[v].Script)))
                {
                    string op = txid + ":" + v;
                    _utxos[op] = (tx.Outputs[v].Value, tx.Outputs[v].Script);
                    _proofs[op] = env;                                        // stored ALWAYS, for handoff
                }
        }
        return true;
    }

    public long Balance() { lock (_lock) { long s = 0; foreach (var c in _utxos.Values) s += c.value; return s; } }
    /// <summary>The stored proof for a coin — handed to the next payee when this coin is spent.</summary>
    public SpvEnvelope? ProofFor(string outpoint) { lock (_lock) return _proofs.TryGetValue(outpoint, out var e) ? e : null; }
    public void Spend(string outpoint) { lock (_lock) { _utxos.Remove(outpoint); _proofs.Remove(outpoint); } }
    public int CoinCount { get { lock (_lock) return _utxos.Count; } }
}
