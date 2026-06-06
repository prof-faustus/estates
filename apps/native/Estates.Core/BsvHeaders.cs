// Estates.Core/BsvHeaders.cs — block headers + PROOF-OF-WORK validation, library-free. This is the
// SPV core of the in-client node: it parses 80-byte headers, computes the block hash (double
// SHA-256), decodes the compact `nBits` difficulty target, and checks that a header actually MEETS
// its proof of work (hash ≤ target). With this, the client validates the header chain it learns
// from peers WITHOUT trusting anyone — the basis for on-chain (SPV) verification of every tx.
//
// A header is 80 bytes: version(4 LE) ‖ prevHash(32) ‖ merkleRoot(32) ‖ time(4 LE) ‖ bits(4 LE) ‖
// nonce(4 LE). The block hash is double-SHA256 of those 80 bytes, displayed reversed (big-endian).
using System.Numerics;

namespace Estates.Core;

public sealed record BlockHeader(
    uint Version, byte[] PrevHash, byte[] MerkleRoot, uint Time, uint Bits, uint Nonce, byte[] Raw)
{
    /// <summary>The block hash (double-SHA256 of the 80 raw bytes), internal byte order.</summary>
    public byte[] Hash() => Tx.Hash256(Raw);
    /// <summary>The conventional big-endian hex id (the hash, reversed).</summary>
    public string Id() { byte[] h = Hash(); Array.Reverse(h); return Tx.ToHex(h); }
}

public static class BsvHeaders
{
    /// <summary>TOTAL parse of an 80-byte header. Returns null on wrong length (never throws).</summary>
    public static BlockHeader? Parse(byte[] raw)
    {
        if (raw is null || raw.Length != 80) return null;
        uint ver = U32(raw, 0);
        byte[] prev = raw[4..36];
        byte[] root = raw[36..68];
        uint time = U32(raw, 68);
        uint bits = U32(raw, 72);
        uint nonce = U32(raw, 76);
        return new BlockHeader(ver, prev, root, time, bits, nonce, raw);
    }

    /// <summary>Decode the compact "nBits" representation into the full 256-bit target.
    /// target = mantissa · 256^(exponent-3). Rejects the negative-sign and overflow cases.</summary>
    public static BigInteger CompactToTarget(uint bits)
    {
        int exponent = (int)(bits >> 24);
        uint mantissa = bits & 0x007fffff;
        if ((bits & 0x00800000) != 0) return BigInteger.MinusOne;   // negative sign set → invalid
        BigInteger target;
        if (exponent <= 3) target = new BigInteger(mantissa) >> (8 * (3 - exponent));
        else target = new BigInteger(mantissa) << (8 * (exponent - 3));
        return target;
    }

    /// <summary>True iff the header actually meets its stated proof of work: the block hash, read as a
    /// 256-bit little-endian integer, is ≤ the target encoded by nBits (and the target is valid/nonzero).</summary>
    public static bool MeetsProofOfWork(BlockHeader h)
    {
        BigInteger target = CompactToTarget(h.Bits);
        if (target <= 0) return false;
        BigInteger max = BigInteger.One << 256;
        if (target >= max) return false;
        byte[] hash = h.Hash();                                       // internal (little-endian) order
        var value = new BigInteger(hash, isUnsigned: true, isBigEndian: false);
        return value <= target;
    }

    /// <summary>Verify a contiguous header chain: each header links to the prior by prevHash, each
    /// meets its own PoW. (Difficulty-retarget validation is layered on top by the chain manager.)
    /// `expectedFirstPrev` pins the parent of headers[0]. Total: false on any break.</summary>
    public static bool VerifyChain(IReadOnlyList<BlockHeader> headers, byte[] expectedFirstPrev)
    {
        byte[] prev = expectedFirstPrev;
        foreach (var h in headers)
        {
            if (!h.PrevHash.AsSpan().SequenceEqual(prev)) return false;
            if (!MeetsProofOfWork(h)) return false;
            prev = h.Hash();
        }
        return true;
    }

    private static uint U32(byte[] b, int off) { uint v = 0; for (int i = 0; i < 4; i++) v |= (uint)b[off + i] << (8 * i); return v; }
}
