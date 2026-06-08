// Estates.Core/PartialMerkleTree.cs — BIP37 merkleblock partial merkle tree, in-tree. Given a block's
// transaction ids and which ones a Bloom filter matched, BUILD the compact (flags + hashes) proof that a
// peer sends; EXTRACT re-derives the merkle root and the matched txids so an SPV client can verify the
// matches belong to the block WITHOUT the full block. Hashes are 32-byte internal (little-endian) txids;
// pairing is double-SHA256. Total/defensive: malformed input → null root.
using System.Collections.Generic;
using System.Linq;

namespace Estates.Core;

public static class PartialMerkleTree
{
    /// <summary>Build the (flags, hashes) merkleblock proof. `txids` are internal-order 32-byte hashes;
    /// `matches[i]` marks transaction i as matched.</summary>
    public static (List<bool> flags, List<byte[]> hashes) Build(IReadOnlyList<byte[]> txids, IReadOnlyList<bool> matches)
    {
        int n = txids.Count;
        int height = 0; while ((1 << height) < n) height++;
        var flags = new List<bool>(); var hashes = new List<byte[]>();
        void Traverse(int h, int pos)
        {
            bool parentMatch = false;
            for (int p = pos << h; p < ((pos + 1) << h) && p < n; p++) if (matches[p]) parentMatch = true;
            flags.Add(parentMatch);
            if (h == 0 || !parentMatch) hashes.Add(CalcHash(h, pos, txids, n));
            else { Traverse(h - 1, pos * 2); if (((pos * 2 + 1) << (h - 1)) < n) Traverse(h - 1, pos * 2 + 1); }
        }
        Traverse(height, 0);
        return (flags, hashes);
    }

    private static byte[] CalcHash(int h, int pos, IReadOnlyList<byte[]> txids, int n)
    {
        if (h == 0) return txids[pos];
        var left = CalcHash(h - 1, pos * 2, txids, n);
        var right = ((pos * 2 + 1) << (h - 1)) < n ? CalcHash(h - 1, pos * 2 + 1, txids, n) : left;
        return Tx.Hash256(Concat(left, right));
    }

    /// <summary>Extract the merkle root + the matched txids from a (flags, hashes) proof for `numTx`
    /// transactions. null root on malformed/forged input (incl. the duplicate-right CVE guard).</summary>
    public static (byte[]? root, List<byte[]> matched) Extract(int numTx, IReadOnlyList<bool> flags, IReadOnlyList<byte[]> hashes)
    {
        var matched = new List<byte[]>();
        if (numTx <= 0) return (null, matched);
        int height = 0; while ((1 << height) < numTx) height++;
        int fi = 0, hi = 0; bool bad = false;
        byte[]? Traverse(int h, int pos)
        {
            if (fi >= flags.Count) { bad = true; return null; }
            bool flag = flags[fi++];
            if (h == 0 || !flag)
            {
                if (hi >= hashes.Count) { bad = true; return null; }
                var hash = hashes[hi++];
                if (h == 0 && flag) matched.Add(hash);
                return hash;
            }
            var left = Traverse(h - 1, pos * 2); if (left is null) return null;
            byte[]? right;
            if (((pos * 2 + 1) << (h - 1)) < numTx)
            {
                right = Traverse(h - 1, pos * 2 + 1); if (right is null) return null;
                if (right.SequenceEqual(left)) { bad = true; return null; }   // identical L/R forbidden (CVE-2012-2459)
            }
            else right = left;
            return Tx.Hash256(Concat(left, right));
        }
        var root = Traverse(height, 0);
        if (bad) return (null, matched);
        return (root, matched);
    }

    private static byte[] Concat(byte[] a, byte[] b) { var o = new byte[a.Length + b.Length]; System.Array.Copy(a, o, a.Length); System.Array.Copy(b, 0, o, a.Length, b.Length); return o; }
}
