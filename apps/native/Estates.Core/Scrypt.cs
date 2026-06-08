// Estates.Core/Scrypt.cs — scrypt (RFC 7914) in-tree, no external libraries. Needed for BIP38 private-key
// decryption (sweep). Salsa20/8 core → BlockMix → ROMix → scrypt, with PBKDF2-HMAC-SHA256 (from the BCL)
// for the inner/outer KDF passes. Verified against the BIP38 test vector in conformance.
using System.Security.Cryptography;

namespace Estates.Core;

public static class Scrypt
{
    public static byte[] DeriveKey(byte[] password, byte[] salt, int n, int r, int p, int dkLen)
    {
        if (n < 2 || (n & (n - 1)) != 0) throw new System.ArgumentException("N must be a power of 2 > 1");
        int blockSize = 128 * r;
        byte[] b = Rfc2898DeriveBytes.Pbkdf2(password, salt, 1, HashAlgorithmName.SHA256, p * blockSize);
        for (int i = 0; i < p; i++)
        {
            var bi = new byte[blockSize];
            System.Array.Copy(b, i * blockSize, bi, 0, blockSize);
            ROMix(bi, n, r);
            System.Array.Copy(bi, 0, b, i * blockSize, blockSize);
        }
        return Rfc2898DeriveBytes.Pbkdf2(password, b, 1, HashAlgorithmName.SHA256, dkLen);
    }

    private static void ROMix(byte[] block, int n, int r)
    {
        int blockSize = 128 * r;
        var x = (byte[])block.Clone();
        var v = new byte[n][];
        for (int i = 0; i < n; i++) { v[i] = (byte[])x.Clone(); BlockMix(x, r); }
        for (int i = 0; i < n; i++)
        {
            // j = Integerify(X) mod N — last 64-byte block's first 4 bytes, little-endian
            long j = System.BitConverter.ToUInt32(x, (2 * r - 1) * 64) & (uint)(n - 1);
            var vj = v[j];
            for (int k = 0; k < blockSize; k++) x[k] ^= vj[k];
            BlockMix(x, r);
        }
        System.Array.Copy(x, block, blockSize);
    }

    // BlockMix: B (2r 64-byte blocks) → output reordered (even blocks then odd blocks), in place.
    private static void BlockMix(byte[] b, int r)
    {
        var x = new byte[64];
        System.Array.Copy(b, (2 * r - 1) * 64, x, 0, 64);
        var y = new byte[128 * r];
        for (int i = 0; i < 2 * r; i++)
        {
            for (int k = 0; k < 64; k++) x[k] ^= b[i * 64 + k];
            Salsa8(x);
            System.Array.Copy(x, 0, y, i * 64, 64);
        }
        for (int i = 0; i < r; i++) System.Array.Copy(y, (2 * i) * 64, b, i * 64, 64);
        for (int i = 0; i < r; i++) System.Array.Copy(y, (2 * i + 1) * 64, b, (r + i) * 64, 64);
    }

    private static uint Rotl(uint a, int b) => (a << b) | (a >> (32 - b));

    // Salsa20/8 core on a 64-byte block (in place).
    private static void Salsa8(byte[] block)
    {
        var x = new uint[16];
        for (int i = 0; i < 16; i++) x[i] = System.BitConverter.ToUInt32(block, i * 4);
        var w = (uint[])x.Clone();
        for (int i = 0; i < 8; i += 2)
        {
            w[4] ^= Rotl(w[0] + w[12], 7); w[8] ^= Rotl(w[4] + w[0], 9); w[12] ^= Rotl(w[8] + w[4], 13); w[0] ^= Rotl(w[12] + w[8], 18);
            w[9] ^= Rotl(w[5] + w[1], 7); w[13] ^= Rotl(w[9] + w[5], 9); w[1] ^= Rotl(w[13] + w[9], 13); w[5] ^= Rotl(w[1] + w[13], 18);
            w[14] ^= Rotl(w[10] + w[6], 7); w[2] ^= Rotl(w[14] + w[10], 9); w[6] ^= Rotl(w[2] + w[14], 13); w[10] ^= Rotl(w[6] + w[2], 18);
            w[3] ^= Rotl(w[15] + w[11], 7); w[7] ^= Rotl(w[3] + w[15], 9); w[11] ^= Rotl(w[7] + w[3], 13); w[15] ^= Rotl(w[11] + w[7], 18);
            w[1] ^= Rotl(w[0] + w[3], 7); w[2] ^= Rotl(w[1] + w[0], 9); w[3] ^= Rotl(w[2] + w[1], 13); w[0] ^= Rotl(w[3] + w[2], 18);
            w[6] ^= Rotl(w[5] + w[4], 7); w[7] ^= Rotl(w[6] + w[5], 9); w[4] ^= Rotl(w[7] + w[6], 13); w[5] ^= Rotl(w[4] + w[7], 18);
            w[11] ^= Rotl(w[10] + w[9], 7); w[8] ^= Rotl(w[11] + w[10], 9); w[9] ^= Rotl(w[8] + w[11], 13); w[10] ^= Rotl(w[9] + w[8], 18);
            w[12] ^= Rotl(w[15] + w[14], 7); w[13] ^= Rotl(w[12] + w[15], 9); w[14] ^= Rotl(w[13] + w[12], 13); w[15] ^= Rotl(w[14] + w[13], 18);
        }
        for (int i = 0; i < 16; i++) { uint v = x[i] + w[i]; System.Array.Copy(System.BitConverter.GetBytes(v), 0, block, i * 4, 4); }
    }
}
