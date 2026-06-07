// Estates.Core/Mempool.cs — the node's MEMPOOL, built from scratch. It holds validated, unconfirmed
// transactions waiting for a block. It rejects malformed transactions, duplicates, and double-spends
// (two transactions spending the same outpoint) by tracking every spent outpoint. When a block
// arrives, the confirmed transactions are evicted and any now-mined conflicts are dropped.
namespace Estates.Core;

public sealed class Mempool
{
    public sealed record MemTx(string Txid, NativeTx Tx, byte[] Raw);

    private readonly object _lock = new();
    private readonly Dictionary<string, MemTx> _byId = new();
    private readonly Dictionary<string, string> _spent = new();   // "txid:vout" -> spending txid
    public int Count { get { lock (_lock) return _byId.Count; } }

    private static string Op(string txid, long vout) => txid + ":" + vout;

    /// <summary>Try to admit a raw transaction. Returns its txid on success, or null if it is
    /// malformed, a duplicate, or conflicts with (double-spends) an already-pooled transaction.</summary>
    public string? Accept(byte[] raw)
    {
        var tx = Tx.Parse(raw);
        if (tx is null || tx.Inputs.Count == 0 || tx.Outputs.Count == 0) return null;
        lock (_lock)
        {
            string txid = Tx.Txid(tx);
            if (_byId.ContainsKey(txid)) return null;                                   // duplicate
            foreach (var i in tx.Inputs) if (_spent.ContainsKey(Op(i.PrevTxid, i.PrevVout))) return null;   // double-spend
            _byId[txid] = new MemTx(txid, tx, raw);
            foreach (var i in tx.Inputs) _spent[Op(i.PrevTxid, i.PrevVout)] = txid;
            return txid;
        }
    }

    public bool Contains(string txid) { lock (_lock) return _byId.ContainsKey(txid); }
    public IReadOnlyList<MemTx> All() { lock (_lock) return _byId.Values.ToList(); }

    /// <summary>A block confirmed these transactions: evict them and any pooled conflicts they mined.</summary>
    public void OnBlock(ParsedBlock blk)
    {
        lock (_lock)
        {
            foreach (var btx in blk.Txs)
            {
                string id = Tx.Txid(btx);
                Evict(id);
                foreach (var i in btx.Inputs)
                    if (_spent.TryGetValue(Op(i.PrevTxid, i.PrevVout), out var sid) && sid != id) Evict(sid);   // conflict now mined
            }
        }
    }

    private void Evict(string txid)
    {
        if (_byId.Remove(txid, out var m)) foreach (var i in m.Tx.Inputs) _spent.Remove(Op(i.PrevTxid, i.PrevVout));
    }
}
