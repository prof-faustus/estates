// Estates.Core/BlockMerkle.cs — build a coin's MERKLE BRANCH from a block's transaction list, from
// scratch. Given the ordered txids of the block that mined a transaction (a BSV mining node returns
// them), this computes the branch + index so the receiver can verify inclusion with MerkleProof against
// the header's merkle root. This is how the funder turns a real mined coin into an SPV envelope to hand
// to the estate node IP-to-IP — no full block, no sync. Bitcoin double-SHA256; duplicates the last node
// on odd levels, exactly as consensus does.
namespace Estates.Core;

public static class BlockMerkle
{
    /// <summary>The merkle branch (display-order sibling hashes) + leaf index for `targetDisplay` within
    /// the block whose ordered txids are `txidsDisplay`. null if the target is not in the block.
    /// MerkleProof.Verify(target, branch, index, root) holds for the returned values.</summary>
    public static (List<string> branch, long index)? BranchFor(IReadOnlyList<string> txidsDisplay, string targetDisplay)
    {
        int idx = -1;
        var level = new List<byte[]>(txidsDisplay.Count);
        for (int i = 0; i < txidsDisplay.Count; i++)
        {
            byte[] h; try { h = Tx.FromHex(txidsDisplay[i]); } catch { return null; }
            if (h.Length != 32) return null;
            System.Array.Reverse(h);                         // display -> internal
            level.Add(h);
            if (string.Equals(txidsDisplay[i], targetDisplay, System.StringComparison.OrdinalIgnoreCase)) idx = i;
        }
        if (idx < 0 || level.Count == 0) return null;

        var branch = new List<string>();
        long index = idx;
        int cur = idx;
        while (level.Count > 1)
        {
            if (level.Count % 2 == 1) level.Add((byte[])level[^1].Clone());   // consensus: duplicate the last
            int sib = (cur % 2 == 0) ? cur + 1 : cur - 1;
            var s = (byte[])level[sib].Clone(); System.Array.Reverse(s);       // internal -> display for the branch
            branch.Add(Tx.ToHex(s));
            var next = new List<byte[]>(level.Count / 2);
            for (int i = 0; i < level.Count; i += 2)
            {
                var pair = new byte[64];
                System.Array.Copy(level[i], 0, pair, 0, 32);
                System.Array.Copy(level[i + 1], 0, pair, 32, 32);
                next.Add(Tx.Hash256(pair));
            }
            level = next; cur /= 2;
        }
        return (branch, index);
    }

    /// <summary>The block's merkle root (internal byte order) from its ordered txids — to cross-check a
    /// header's merkle root.</summary>
    public static byte[] Root(IReadOnlyList<string> txidsDisplay)
    {
        var level = new List<byte[]>();
        foreach (var t in txidsDisplay) { var h = Tx.FromHex(t); System.Array.Reverse(h); level.Add(h); }
        if (level.Count == 0) return new byte[32];
        while (level.Count > 1)
        {
            if (level.Count % 2 == 1) level.Add((byte[])level[^1].Clone());
            var next = new List<byte[]>();
            for (int i = 0; i < level.Count; i += 2) { var p = new byte[64]; System.Array.Copy(level[i], 0, p, 0, 32); System.Array.Copy(level[i + 1], 0, p, 32, 32); next.Add(Tx.Hash256(p)); }
            level = next;
        }
        return level[0];
    }
}
