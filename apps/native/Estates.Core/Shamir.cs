// Estates.Core/Shamir.cs — PLAN §2 threshold scheme (from the user's anchorchain/custody design),
// written from scratch on the in-tree secp256k1 scalar field (mod n). Microsoft BCL only. NO library.
//
// Shamir (t,n) secret sharing over GF(n): a secret s is the constant term of a random degree-(t-1)
// polynomial; n shares are (x, P(x)) mod n; ANY t shares reconstruct s by Lagrange interpolation at
// 0; fewer than t reveal nothing. Used for the user's threshold recovery/custody so funds are never
// lost and no single party (or seized node) controls them.
using System.Numerics;
using System.Security.Cryptography;

namespace Estates.Core;

public static class Shamir
{
    private static BigInteger N => Secp256k1.NOrder;
    private static BigInteger Mod(BigInteger a) { var r = a % N; return r.Sign < 0 ? r + N : r; }
    private static BigInteger Inv(BigInteger a) => BigInteger.ModPow(Mod(a), N - 2, N);   // n prime
    private static BigInteger Rand() => new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true, isBigEndian: true) % N;

    public sealed record Share(int X, byte[] Y);

    /// <summary>Split a ≤32-byte secret into `shares` shares; any `threshold` reconstruct it.</summary>
    public static List<Share> Split(byte[] secret, int threshold, int shares)
    {
        if (threshold < 1 || threshold > shares || shares > 255) throw new ArgumentException("need 1 ≤ threshold ≤ shares ≤ 255");
        var coeff = new BigInteger[threshold];
        coeff[0] = new BigInteger(secret, isUnsigned: true, isBigEndian: true) % N;
        for (int i = 1; i < threshold; i++) coeff[i] = Rand();
        var outp = new List<Share>(shares);
        for (int x = 1; x <= shares; x++)
        {
            BigInteger y = 0, xp = 1;
            for (int j = 0; j < threshold; j++) { y = Mod(y + coeff[j] * xp); xp = Mod(xp * x); }
            outp.Add(new Share(x, Secp256k1.To32(y)));
        }
        return outp;
    }

    /// <summary>Reconstruct the secret from `threshold` (or more) shares via Lagrange interpolation at 0.</summary>
    public static byte[] Reconstruct(IReadOnlyList<Share> shares)
    {
        BigInteger secret = 0;
        for (int i = 0; i < shares.Count; i++)
        {
            BigInteger num = 1, den = 1;
            for (int j = 0; j < shares.Count; j++)
            {
                if (i == j) continue;
                num = Mod(num * (0 - shares[j].X));
                den = Mod(den * (shares[i].X - shares[j].X));
            }
            BigInteger li = Mod(num * Inv(den));
            secret = Mod(secret + new BigInteger(shares[i].Y, isUnsigned: true, isBigEndian: true) * li);
        }
        return Secp256k1.To32(secret);
    }
}
