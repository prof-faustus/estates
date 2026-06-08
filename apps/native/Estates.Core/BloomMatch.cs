// Estates.Core/BloomMatch.cs — BIP37 transaction matching against a wallet's Bloom filter (the "find"
// in bloom → merkleblock → find → envelope). A wallet loads a filter over the things it cares about
// (its address pubkey-hashes, its txids, its spent outpoints); a transaction MATCHES if the filter
// contains its txid, any output's P2PKH pubkey-hash, or any input's spent outpoint. Matching is what a
// serving peer applies to decide which transactions to return + include in the merkleblock proof.
using System.Collections.Generic;

namespace Estates.Core;

public static class BloomMatch
{
    /// <summary>True if `tx` (with internal-order `txidInternal`) matches the filter.</summary>
    public static bool Matches(NativeTx tx, byte[] txidInternal, BloomFilter f)
    {
        if (f.Contains(txidInternal)) return true;                       // the txid itself
        foreach (var o in tx.Outputs)
        {
            var pkh = P2pkhPkh(o.Script);
            if (pkh is not null && f.Contains(pkh)) return true;         // an output paying a watched address
        }
        foreach (var i in tx.Inputs)
            if (f.Contains(Outpoint(i.PrevTxid, i.PrevVout))) return true;   // a watched outpoint being spent
        return false;
    }

    /// <summary>What a wallet inserts into its filter: each watched address pubkey-hash.</summary>
    public static void InsertAddress(BloomFilter f, byte[] pkh20) => f.Insert(pkh20);

    /// <summary>The 36-byte outpoint encoding inserted/tested for inputs: txid(internal,32) ‖ vout(LE32).</summary>
    public static byte[] Outpoint(string txidDisplay, long vout)
    {
        byte[] disp = Tx.FromHex(txidDisplay);
        var internalTxid = (byte[])disp.Clone(); System.Array.Reverse(internalTxid);
        var o = new byte[36]; System.Array.Copy(internalTxid, o, 32);
        o[32] = (byte)vout; o[33] = (byte)(vout >> 8); o[34] = (byte)(vout >> 16); o[35] = (byte)(vout >> 24);
        return o;
    }

    /// <summary>The 20-byte pubkey-hash of a standard P2PKH locking script, or null.</summary>
    public static byte[]? P2pkhPkh(byte[] script)
    {
        if (script.Length == 25 && script[0] == 0x76 && script[1] == 0xa9 && script[2] == 0x14 && script[23] == 0x88 && script[24] == 0xac)
            return script[3..23];
        return null;
    }
}
