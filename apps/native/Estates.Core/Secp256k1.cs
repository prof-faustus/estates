// Estates.Core/Secp256k1.cs — in-tree secp256k1 (NO third-party library). Pure C# over
// System.Numerics.BigInteger: field arithmetic mod p, affine point add/double/multiply,
// compressed point encode/decode, ECDH, and ECDSA (CSPRNG random nonce k, low-S; NO RFC-6979).
// This REPLACES BouncyCastle everywhere — the project depends on no crypto library.
// (SHA-256/512, HMAC, AES-GCM, HKDF are .NET framework primitives, not a library.)
using System.Numerics;
using System.Security.Cryptography;

namespace Estates.Core;

public static class Secp256k1
{
    // secp256k1 domain parameters (SEC 2).
    public static readonly BigInteger P = BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", System.Globalization.NumberStyles.HexNumber);
    public static readonly BigInteger N = BigInteger.Parse("0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger Gx = BigInteger.Parse("079BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger Gy = BigInteger.Parse("0483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", System.Globalization.NumberStyles.HexNumber);
    private static readonly BigInteger HalfN = N >> 1;

    public readonly record struct Point(BigInteger X, BigInteger Y, bool Inf)
    {
        public static readonly Point Identity = new(0, 0, true);
    }
    public static readonly Point G = new(Gx, Gy, false);

    private static BigInteger Mod(BigInteger a, BigInteger m) { var r = a % m; return r.Sign < 0 ? r + m : r; }
    private static BigInteger InvMod(BigInteger a, BigInteger m) => BigInteger.ModPow(Mod(a, m), m - 2, m); // p,n prime

    // ---- point arithmetic (affine) ----
    public static Point Add(Point p, Point q)
    {
        if (p.Inf) return q;
        if (q.Inf) return p;
        if (p.X == q.X)
        {
            if (Mod(p.Y + q.Y, P) == 0) return Point.Identity;   // p == -q
            return Double(p);
        }
        BigInteger s = Mod((q.Y - p.Y) * InvMod(q.X - p.X, P), P);
        BigInteger rx = Mod(s * s - p.X - q.X, P);
        BigInteger ry = Mod(s * (p.X - rx) - p.Y, P);
        return new Point(rx, ry, false);
    }

    public static Point Double(Point p)
    {
        if (p.Inf || p.Y == 0) return Point.Identity;
        BigInteger s = Mod((3 * p.X * p.X) * InvMod(2 * p.Y, P), P);   // a = 0
        BigInteger rx = Mod(s * s - 2 * p.X, P);
        BigInteger ry = Mod(s * (p.X - rx) - p.Y, P);
        return new Point(rx, ry, false);
    }

    public static Point Mul(BigInteger k, Point p)
    {
        k = Mod(k, N);
        var r = Point.Identity;
        var addend = p;
        while (k > 0)
        {
            if (!k.IsEven) r = Add(r, addend);
            addend = Double(addend);
            k >>= 1;
        }
        return r;
    }

    // ---- scalars / encoding ----
    private static BigInteger Scalar(byte[] priv) => Mod(FromBytes(priv), N);
    private static BigInteger FromBytes(byte[] b) => new(Prepend0(b), isUnsigned: true, isBigEndian: true);
    private static byte[] Prepend0(byte[] b) { var o = new byte[b.Length + 1]; Array.Copy(b, 0, o, 1, b.Length); return o; }

    public static byte[] To32(BigInteger x)
    {
        byte[] b = x.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (b.Length == 32) return b;
        var o = new byte[32];
        Array.Copy(b, 0, o, 32 - b.Length, Math.Min(b.Length, 32));
        return o;
    }

    /// <summary>Compressed (33-byte) public key for a 32-byte private key.</summary>
    public static byte[] PublicKey(byte[] priv) => Compress(Mul(Scalar(priv), G));

    public static byte[] Compress(Point p)
    {
        var o = new byte[33];
        o[0] = (byte)(p.Y.IsEven ? 0x02 : 0x03);
        Array.Copy(To32(p.X), 0, o, 1, 32);
        return o;
    }

    public static Point Decompress(byte[] pub)
    {
        if (pub.Length == 33 && (pub[0] == 0x02 || pub[0] == 0x03))
        {
            BigInteger x = FromBytes(pub[1..]);
            BigInteger y2 = Mod(BigInteger.ModPow(x, 3, P) + 7, P);
            BigInteger y = BigInteger.ModPow(y2, (P + 1) / 4, P);   // p ≡ 3 (mod 4)
            if (y.IsEven != (pub[0] == 0x02)) y = P - y;
            return new Point(x, y, false);
        }
        if (pub.Length == 65 && pub[0] == 0x04)
            return new Point(FromBytes(pub[1..33]), FromBytes(pub[33..]), false);
        throw new ArgumentException("bad public key encoding");
    }

    /// <summary>ECDH shared secret = compressed point (priv·peerPub).</summary>
    public static byte[] EcdhCompressed(byte[] priv, byte[] peerPub) => Compress(Mul(Scalar(priv), Decompress(peerPub)));
    /// <summary>ECDH shared secret = the X coordinate (32 bytes) of priv·peerPub.</summary>
    public static byte[] EcdhX(byte[] priv, byte[] peerPub) => To32(Mul(Scalar(priv), Decompress(peerPub)).X);

    // ---- ECDSA (CSPRNG random nonce k, low-S). NO deterministic/RFC-6979 nonce — each signature
    //      draws a fresh uniformly-random k in [1, n-1] from the OS CSPRNG via rejection sampling. ----
    private static BigInteger RandomK()
    {
        while (true)
        {
            BigInteger k = new(RandomNumberGenerator.GetBytes(32), isUnsigned: true, isBigEndian: true);
            if (k >= 1 && k < N) return k;
        }
    }

    /// <summary>Sign a 32-byte hash; returns (r, s) with low-S. The nonce k is freshly random.</summary>
    public static (BigInteger r, BigInteger s) SignHash(byte[] priv, byte[] hash32)
    {
        BigInteger d = Scalar(priv), z = Mod(FromBytes(hash32), N);
        while (true)
        {
            BigInteger k = RandomK();
            Point R = Mul(k, G);
            BigInteger r = Mod(R.X, N);
            if (r == 0) continue;
            BigInteger s = Mod(InvMod(k, N) * (z + r * d), N);
            if (s == 0) continue;
            if (s > HalfN) s = N - s;   // low-S
            return (r, s);
        }
    }

    /// <summary>Verify (r,s) over a 32-byte hash against a public key; rejects high-S.</summary>
    public static bool VerifyHash(byte[] pub, byte[] hash32, BigInteger r, BigInteger s)
    {
        try
        {
            if (r < 1 || r >= N || s < 1 || s >= N || s > HalfN) return false;
            BigInteger z = Mod(FromBytes(hash32), N);
            BigInteger w = InvMod(s, N);
            Point R = Add(Mul(Mod(z * w, N), G), Mul(Mod(r * w, N), Decompress(pub)));
            if (R.Inf) return false;
            return Mod(R.X, N) == r;
        }
        catch { return false; }
    }

    public static BigInteger ScalarAddModN(byte[] a, BigInteger b) => Mod(FromBytes(a) + b, N);
    public static BigInteger NOrder => N;
}
