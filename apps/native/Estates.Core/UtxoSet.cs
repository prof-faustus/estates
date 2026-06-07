// Estates.Core/UtxoSet.cs — the node's UTXO LEDGER, built from scratch (no library). It is the
// authoritative set of unspent outputs, produced by applying validated blocks. This is what gives the
// wallet a REAL balance — never a manual import: a key's P2PKH script is looked up here. Coinbase
// outputs are flagged and counted as IMMATURE until 100 confirmations, then SPENDABLE. This is the
// ledger half of the full node we are building (the other halves: P2P/headers/blocks/mempool/wallet).
namespace Estates.Core;

public sealed class UtxoSet
{
    public sealed record Entry(string Txid, int Vout, long Value, byte[] Script, int Height, bool Coinbase);
    public const int CoinbaseMaturity = 100;

    private readonly object _lock = new();
    private readonly Dictionary<string, Entry> _set = new();
    public int Tip { get; private set; }
    public int Count { get { lock (_lock) return _set.Count; } }

    private static string Key(string txid, long vout) => txid + ":" + vout;
    private bool Mature(Entry e) => !e.Coinbase || (Tip - e.Height + 1) >= CoinbaseMaturity;

    /// <summary>Apply a validated block at `height`: spend the inputs of every non-coinbase tx, then
    /// add every output as a new UTXO. (The coinbase, tx index 0, has no real inputs to spend.)</summary>
    public void ApplyBlock(int height, ParsedBlock blk)
    {
        lock (_lock)
        {
            if (height > Tip) Tip = height;
            for (int t = 0; t < blk.Txs.Count; t++)
            {
                var tx = blk.Txs[t];
                if (t != 0) foreach (var i in tx.Inputs) _set.Remove(Key(i.PrevTxid, i.PrevVout));
                string txid = Tx.Txid(tx);
                for (int v = 0; v < tx.Outputs.Count; v++)
                    _set[Key(txid, v)] = new Entry(txid, v, tx.Outputs[v].Value, tx.Outputs[v].Script, height, t == 0);
            }
        }
    }

    public void SetTip(int height) { lock (_lock) { if (height > Tip) Tip = height; } }
    public Entry? Get(string txid, long vout) { lock (_lock) return _set.TryGetValue(Key(txid, vout), out var e) ? e : null; }
    public long Total() { lock (_lock) { long s = 0; foreach (var e in _set.Values) s += e.Value; return s; } }

    /// <summary>Confirmed + mature balance for a set of owned P2PKH scripts (hex).</summary>
    public long SpendableFor(ISet<string> ownedScriptsHex)
    {
        lock (_lock) { long s = 0; foreach (var e in _set.Values) if (Mature(e) && ownedScriptsHex.Contains(Tx.ToHex(e.Script))) s += e.Value; return s; }
    }
    /// <summary>Mined coinbase not yet 100 confs deep — the proof your mining is yours.</summary>
    public long ImmatureFor(ISet<string> ownedScriptsHex)
    {
        lock (_lock) { long s = 0; foreach (var e in _set.Values) if (!Mature(e) && ownedScriptsHex.Contains(Tx.ToHex(e.Script))) s += e.Value; return s; }
    }
    /// <summary>The spendable UTXOs for coin selection.</summary>
    public IReadOnlyList<Entry> SpendableUtxos(ISet<string> ownedScriptsHex)
    {
        lock (_lock) return _set.Values.Where(e => Mature(e) && ownedScriptsHex.Contains(Tx.ToHex(e.Script))).ToList();
    }
}
