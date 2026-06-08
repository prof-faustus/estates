// Estates.Core/MerkleProof.cs — SPV merkle proof, from scratch. Proves a transaction is included in a
// block WITHOUT the full block: just the txid, its merkle branch (sibling hashes, bottom-up), its
// index, and the block header's merkle root. This is what makes the wallet INSTANT — it admits a coin
// on a verified proof against a header it holds, never downloading or validating the whole chain, and
// it works whether or not it is currently online. Bitcoin double-SHA256; hashes in internal byte order.
namespace Estates.Core;

public static class MerkleProof
{
    /// <summary>Recompute the merkle root from a leaf txid + its branch + index (all internal order).</summary>
    public static byte[] Root(byte[] txidInternal, IReadOnlyList<byte[]> branch, long index)
    {
        var h = (byte[])txidInternal.Clone();
        long idx = index;
        foreach (var sib in branch)
        {
            if (sib.Length != 32) throw new System.FormatException("branch hash must be 32 bytes");
            var pair = new byte[64];
            if ((idx & 1) == 0) { System.Array.Copy(h, 0, pair, 0, 32); System.Array.Copy(sib, 0, pair, 32, 32); }
            else { System.Array.Copy(sib, 0, pair, 0, 32); System.Array.Copy(h, 0, pair, 32, 32); }
            h = Tx.Hash256(pair);
            idx >>= 1;
        }
        return h;
    }

    /// <summary>TOTAL: verify a tx (display txid) is in a block with `merkleRootInternal` (the header's
    /// merkle root) via its branch (display-order sibling hashes) at `index`. False on any malformed
    /// input — never throws.</summary>
    public static bool Verify(string txidDisplay, IReadOnlyList<string> branchDisplay, long index, byte[] merkleRootInternal)
    {
        try
        {
            if (index < 0 || merkleRootInternal is null || merkleRootInternal.Length != 32) return false;
            var h = Tx.FromHex(txidDisplay); if (h.Length != 32) return false; System.Array.Reverse(h);
            long idx = index;
            foreach (var bd in branchDisplay)
            {
                // A "*" (or empty) sibling is the TSC "duplicate" marker: at this level the sibling is the
                // working hash itself (right-edge of an odd row). Otherwise it is a display-order hash.
                byte[] sib;
                if (bd == "*" || bd.Length == 0) sib = (byte[])h.Clone();
                else { sib = Tx.FromHex(bd); if (sib.Length != 32) return false; System.Array.Reverse(sib); }
                var pair = new byte[64];
                if ((idx & 1) == 0) { System.Array.Copy(h, 0, pair, 0, 32); System.Array.Copy(sib, 0, pair, 32, 32); }
                else { System.Array.Copy(sib, 0, pair, 0, 32); System.Array.Copy(h, 0, pair, 32, 32); }
                h = Tx.Hash256(pair);
                idx >>= 1;
            }
            return h.AsSpan().SequenceEqual(merkleRootInternal);
        }
        catch { return false; }
    }
}
