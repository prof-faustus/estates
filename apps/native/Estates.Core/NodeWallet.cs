// Estates.Core/NodeWallet.cs — a REAL node-backed wallet. It owns addresses and ingests blocks +
// mempool transactions from the node the client IS (fed by the P2P layer). Coins appear because the
// node SAW them on the chain — never a manual "add a UTXO". It reports the three balances every real
// wallet shows, live: IMMATURE (your mined coinbase, < 100 confs), UNCONFIRMED (mempool, 0-conf), and
// SPENDABLE (confirmed & mature). This is what proves your mining is yours the instant a block lands.
namespace Estates.Core;

public sealed class NodeWallet
{
    public const int CoinbaseMaturity = 100;

    public sealed record WIn(string Txid, int Vout);
    public sealed record WOut(long Value, byte[] Script);
    public sealed record WTx(string Txid, IReadOnlyList<WIn> Inputs, IReadOnlyList<WOut> Outputs);

    public sealed record Utxo(string Txid, int Vout, long Value, int Height, bool Coinbase);

    private readonly object _lock = new();
    private readonly Dictionary<string, Utxo> _utxos = new();   // "txid:vout" -> utxo
    private readonly HashSet<string> _myScripts = new();        // P2PKH scripts (hex) this wallet owns
    public int TipHeight { get; private set; }

    /// <summary>Construct from the wallet's public keys; the wallet recognises pays to their P2PKH.</summary>
    public NodeWallet(IEnumerable<byte[]> myPubkeys)
    {
        foreach (var pub in myPubkeys)
            _myScripts.Add(Tx.ToHex(P2pkhScript(Recovery.Hash160(pub))));
    }

    /// <summary>The standard P2PKH script for a 20-byte pubkey hash.</summary>
    public static byte[] P2pkhScript(byte[] pkh)
    {
        var s = new byte[25];
        s[0] = 0x76; s[1] = 0xa9; s[2] = 20; Array.Copy(pkh, 0, s, 3, 20); s[23] = 0x88; s[24] = 0xac;
        return s;
    }

    public void SetTip(int height) { lock (_lock) { if (height > TipHeight) TipHeight = height; } }

    /// <summary>Apply a CONFIRMED block at `height`: index outputs paying me (the first tx is the
    /// coinbase), and remove any of my UTXOs its inputs spend.</summary>
    public void ApplyBlock(int height, IReadOnlyList<WTx> txs)
    {
        lock (_lock)
        {
            if (height > TipHeight) TipHeight = height;
            for (int t = 0; t < txs.Count; t++)
            {
                var tx = txs[t];
                foreach (var i in tx.Inputs) _utxos.Remove($"{i.Txid}:{i.Vout}");
                for (int v = 0; v < tx.Outputs.Count; v++)
                {
                    var o = tx.Outputs[v];
                    if (_myScripts.Contains(Tx.ToHex(o.Script)))
                        _utxos[$"{tx.Txid}:{v}"] = new Utxo(tx.Txid, v, o.Value, height, t == 0);
                }
            }
        }
    }

    /// <summary>Apply an UNCONFIRMED (mempool) tx: my new outputs become 0-conf, spent inputs drop.</summary>
    public void ApplyMempoolTx(WTx tx)
    {
        lock (_lock)
        {
            foreach (var i in tx.Inputs) _utxos.Remove($"{i.Txid}:{i.Vout}");
            for (int v = 0; v < tx.Outputs.Count; v++)
            {
                var o = tx.Outputs[v];
                if (_myScripts.Contains(Tx.ToHex(o.Script)))
                    _utxos[$"{tx.Txid}:{v}"] = new Utxo(tx.Txid, v, o.Value, 0, false);
            }
        }
    }

    private int Confs(Utxo u) => u.Height == 0 ? 0 : TipHeight - u.Height + 1;
    private bool ImmatureCoinbase(Utxo u) => u.Coinbase && Confs(u) < CoinbaseMaturity;

    /// <summary>Mined coinbase not yet 100 confs deep — shown, because a real wallet shows it.</summary>
    public long Immature() { lock (_lock) return _utxos.Values.Where(ImmatureCoinbase).Sum(u => u.Value); }
    /// <summary>In the mempool (0-conf).</summary>
    public long Unconfirmed() { lock (_lock) return _utxos.Values.Where(u => u.Height == 0).Sum(u => u.Value); }
    /// <summary>Confirmed and mature — actually spendable.</summary>
    public long Spendable() { lock (_lock) return _utxos.Values.Where(u => u.Height > 0 && !ImmatureCoinbase(u)).Sum(u => u.Value); }
    public long Total() => Immature() + Unconfirmed() + Spendable();
    public int UtxoCount() { lock (_lock) return _utxos.Count; }
}
