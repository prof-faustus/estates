// Estates.Core/Block.cs — a parsed BSV block: the 80-byte header + its transactions. The node checks
// proof-of-work on the header (BsvHeaders) and feeds the transactions into the UTXO ledger (UtxoSet).
// Parsing is TOTAL: any malformed/oversized/truncated block returns null, never throws.
namespace Estates.Core;

public sealed record ParsedBlock(byte[] Header80, string BlockHash, IReadOnlyList<NativeTx> Txs);

public static class Block
{
    /// <summary>Display-order block hash = reverse(double-SHA256(header80)).</summary>
    public static string HashOf(byte[] header80) { var h = Tx.Hash256(header80); System.Array.Reverse(h); return Tx.ToHex(h); }

    /// <summary>Parse a raw block: header(80) ‖ varint(txCount) ‖ txs. null on any malformed input.</summary>
    public static ParsedBlock? Parse(byte[] raw)
    {
        try
        {
            if (raw.Length < 81) return null;
            var hdr = new byte[80]; System.Array.Copy(raw, 0, hdr, 0, 80);
            int pos = 80;
            long n = Tx.ReadVarint(raw, ref pos);
            if (n < 0 || n > 10_000_000) return null;
            var txs = new List<NativeTx>((int)System.Math.Min(n, 8192));
            for (long k = 0; k < n; k++) txs.Add(Tx.Deserialize(raw, ref pos));
            if (pos != raw.Length) return null;          // no trailing bytes — strict
            return new ParsedBlock(hdr, HashOf(hdr), txs);
        }
        catch { return null; }
    }
}
