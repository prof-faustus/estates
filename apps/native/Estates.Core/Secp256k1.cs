// Estates.Core/Secp256k1.cs — in-tree secp256k1 (NO third-party library). Pure C# over
// System.Numerics.BigInteger: field arithmetic mod p, affine point add/double/multiply,
// compressed point encode/decode, ECDH, and ECDSA (fresh CSPRNG random nonce k, low-S).
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

    // ---- FAST scalar multiply via JACOBIAN coordinates (X,Y,Z) ~ affine (X/Z², Y/Z³), a=0. This does ONE
    //      modular inverse at the very end instead of one per point-addition — ~10-50x faster than the affine
    //      double-and-add, which is what makes a 52-card multi-player mental-poker shuffle practical. Standard
    //      formulas (dbl-2009-l, madd-2007-bl); results are identical to the affine math (proven by the vectors).
    private static (BigInteger X, BigInteger Y, BigInteger Z) JDouble((BigInteger X, BigInteger Y, BigInteger Z) p)
    {
        if (p.Z.IsZero || p.Y.IsZero) return (1, 1, 0);   // infinity
        BigInteger A = Mod(p.X * p.X, P);
        BigInteger B = Mod(p.Y * p.Y, P);
        BigInteger C = Mod(B * B, P);
        BigInteger D = Mod(2 * (Mod((p.X + B) * (p.X + B), P) - A - C), P);
        BigInteger E = Mod(3 * A, P);
        BigInteger F = Mod(E * E, P);
        BigInteger X3 = Mod(F - 2 * D, P);
        BigInteger Y3 = Mod(E * (D - X3) - 8 * C, P);
        BigInteger Z3 = Mod(2 * p.Y * p.Z, P);
        return (X3, Y3, Z3);
    }
    private static (BigInteger X, BigInteger Y, BigInteger Z) JAddAffine((BigInteger X, BigInteger Y, BigInteger Z) p, Point q)
    {
        if (p.Z.IsZero) return (q.X, q.Y, 1);
        BigInteger Z1Z1 = Mod(p.Z * p.Z, P);
        BigInteger U2 = Mod(q.X * Z1Z1, P);
        BigInteger S2 = Mod(q.Y * p.Z * Z1Z1, P);
        BigInteger H = Mod(U2 - p.X, P);
        if (H.IsZero) { return Mod(S2 - p.Y, P).IsZero ? JDouble(p) : (1, 1, 0); }
        BigInteger HH = Mod(H * H, P);
        BigInteger I = Mod(4 * HH, P);
        BigInteger J = Mod(H * I, P);
        BigInteger r = Mod(2 * (S2 - p.Y), P);
        BigInteger V = Mod(p.X * I, P);
        BigInteger X3 = Mod(r * r - J - 2 * V, P);
        BigInteger Y3 = Mod(r * (V - X3) - 2 * p.Y * J, P);
        BigInteger Z3 = Mod(Mod((p.Z + H) * (p.Z + H), P) - Z1Z1 - HH, P);
        return (X3, Y3, Z3);
    }

    public static Point Mul(BigInteger k, Point p)
    {
        k = Mod(k, N);
        if (k.IsZero || p.Inf) return Point.Identity;
        var acc = ((BigInteger)0, (BigInteger)0, (BigInteger)0);   // infinity (Z=0)
        for (int i = (int)k.GetBitLength() - 1; i >= 0; i--)
        {
            acc = JDouble(acc);
            if (!((k >> i) & 1).IsZero) acc = JAddAffine(acc, p);
        }
        if (acc.Item3.IsZero) return Point.Identity;
        BigInteger zinv = InvMod(acc.Item3, P);
        BigInteger zinv2 = Mod(zinv * zinv, P);
        return new Point(Mod(acc.Item1 * zinv2, P), Mod(acc.Item2 * zinv2 * zinv, P), false);
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

    // ---- MENTAL-POKER primitives (commutative encryption on the curve). A card i is the fixed public point
    //      Mᵢ = (i+1)·G; "encrypting" a card is scalar-multiplying its point; masks COMMUTE (a·(b·P)=b·(a·P)),
    //      so they strip in any order. These are thin wrappers over the field/point math above. ----

    /// <summary>The fixed PUBLIC base point for card index i: Mᵢ = (i+1)·G (compressed).</summary>
    public static byte[] CardBasePoint(int i)
    {
        if (i < 0) throw new ArgumentOutOfRangeException(nameof(i));
        return Compress(Mul(i + 1, G));
    }

    /// <summary>Scalar-multiply a compressed point by a 32-byte scalar: returns (scalar·P) compressed. This is
    /// one mask/unmask step. Throws on a malformed/off-curve point or a zero/invalid scalar — a hostile player
    /// cannot inject a bad point or a zero scalar into the deal.</summary>
    public static byte[] PointMul(byte[] point33, byte[] scalar)
    {
        if (!IsValidScalar(scalar)) throw new ArgumentException("invalid scalar");
        if (!IsValidPoint(point33)) throw new ArgumentException("invalid/off-curve point");
        return Compress(Mul(Scalar(scalar), Decompress(point33)));
    }

    /// <summary>The modular inverse (mod N) of a scalar, as 32 bytes — used to STRIP a mask (multiply by k⁻¹).
    /// Throws on a zero/invalid scalar (not invertible).</summary>
    public static byte[] ScalarInverse(byte[] scalar)
    {
        if (!IsValidScalar(scalar)) throw new ArgumentException("scalar not invertible (zero or out of range)");
        return To32(InvMod(FromBytes(scalar), N));
    }

    /// <summary>(a * b) mod N as 32 bytes — multiply two scalars (used to COMBINE per-card masks into one).
    /// Both inputs must be valid scalars in [1, N-1]; the product mod the prime N is never zero, so the result
    /// is always a valid, invertible scalar. Throws on a zero/out-of-range input.</summary>
    public static byte[] ScalarMul(byte[] a, byte[] b)
    {
        if (!IsValidScalar(a) || !IsValidScalar(b)) throw new ArgumentException("invalid scalar in ScalarMul");
        return To32(Mod(FromBytes(a) * FromBytes(b), N));
    }

    /// <summary>A scalar is valid iff it is 32 bytes encoding a value in [1, N-1].</summary>
    public static bool IsValidScalar(byte[] s)
    {
        if (s is not { Length: 32 }) return false;
        var x = FromBytes(s);
        return x > 0 && x < N;
    }

    /// <summary>A point is valid iff it is a 33-byte compressed point that lies on the curve and is not the
    /// point at infinity. Total — never throws.</summary>
    public static bool IsValidPoint(byte[] p)
    {
        try
        {
            if (p is not { Length: 33 } || (p[0] != 0x02 && p[0] != 0x03)) return false;
            var pt = Decompress(p);
            if (pt.Inf || pt.X <= 0 || pt.X >= P) return false;
            return Mod(pt.Y * pt.Y - (BigInteger.ModPow(pt.X, 3, P) + 7), P) == 0;   // y² = x³ + 7
        }
        catch { return false; }
    }

    // ---- ECDSA (fresh CSPRNG random nonce k, low-S). Each signature draws a new uniformly-random
    //      k in [1, n-1] from the OS CSPRNG via rejection sampling. ----
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
