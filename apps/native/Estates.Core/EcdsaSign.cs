// Estates.Core/EcdsaSign.cs — secp256k1 ECDSA (BSV), library-free: built on the in-tree
// Secp256k1 + Microsoft .NET only (System.Numerics, System.Security.Cryptography). NO
// third-party library. The nonce is a fresh CSPRNG random k + low-S (Secp256k1.SignHash).
// (Chain txs are signed by the NODE; this is local protocol paths.)
using System.Numerics;
using System.Security.Cryptography;

namespace Estates.Core;

public static class EcdsaSign
{
    /// <summary>The compressed (33-byte) secp256k1 public key for a private key.</summary>
    public static byte[] PublicKey(byte[] priv) => Secp256k1.PublicKey(priv);

    /// <summary>True iff `priv` is a valid secp256k1 scalar (32 bytes, in [1, n-1]).</summary>
    public static bool IsValidScalar(byte[]? priv)
    {
        if (priv is null || priv.Length != 32) return false;
        var d = new BigInteger(priv, isUnsigned: true, isBigEndian: true);
        return d > 0 && d < Secp256k1.NOrder;
    }

    /// <summary>Deterministic low-S ECDSA over SHA-256(message). Returns 64 bytes (r‖s).</summary>
    public static byte[] Sign(byte[] priv, byte[] message)
    {
        var (r, s) = Secp256k1.SignHash(priv, SHA256.HashData(message));
        var o = new byte[64];
        Array.Copy(Secp256k1.To32(r), 0, o, 0, 32);
        Array.Copy(Secp256k1.To32(s), 0, o, 32, 32);
        return o;
    }

    /// <summary>Verify a 64-byte (r‖s) signature over SHA-256(message); rejects high-S. Total.</summary>
    public static bool Verify(byte[] pub, byte[] message, byte[] sig)
    {
        if (sig.Length != 64) return false;
        var r = new BigInteger(sig[..32], isUnsigned: true, isBigEndian: true);
        var s = new BigInteger(sig[32..], isUnsigned: true, isBigEndian: true);
        return Secp256k1.VerifyHash(pub, SHA256.HashData(message), r, s);
    }

    /// <summary>Sign a 32-byte prehash (e.g. a BSV FORKID sighash); returns a DER signature (low-S).</summary>
    public static byte[] SignPrehashDer(byte[] priv, byte[] prehash32)
    {
        var (r, s) = Secp256k1.SignHash(priv, prehash32);
        return DerEncode(r, s);
    }

    /// <summary>Verify a DER signature over a 32-byte prehash against a SEC1 pubkey; rejects high-S.</summary>
    public static bool VerifyDerPrehash(byte[] pubSec1, byte[] prehash32, byte[] der)
    {
        try { var (r, s) = DerDecode(der); return Secp256k1.VerifyHash(pubSec1, prehash32, r, s); }
        catch { return false; }
    }

    // DER INTEGER: minimal big-endian, prepend 0x00 if the high bit is set (positive).
    private static byte[] DerInt(BigInteger v)
    {
        byte[] b = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        int i = 0; while (i < b.Length - 1 && b[i] == 0) i++;
        b = b[i..];
        if ((b[0] & 0x80) != 0) { var o = new byte[b.Length + 1]; Array.Copy(b, 0, o, 1, b.Length); return o; }
        return b;
    }

    private static byte[] DerEncode(BigInteger r, BigInteger s)
    {
        byte[] rb = DerInt(r), sb = DerInt(s);
        var body = new List<byte> { 0x02, (byte)rb.Length }; body.AddRange(rb);
        body.Add(0x02); body.Add((byte)sb.Length); body.AddRange(sb);
        var o = new List<byte> { 0x30, (byte)body.Count }; o.AddRange(body);
        return o.ToArray();
    }

    private static (BigInteger r, BigInteger s) DerDecode(byte[] der)
    {
        int i = 0;
        if (der[i++] != 0x30) throw new FormatException("der");
        i++;
        if (der[i++] != 0x02) throw new FormatException("der");
        int rl = der[i++]; var r = new BigInteger(der[i..(i + rl)], isUnsigned: true, isBigEndian: true); i += rl;
        if (der[i++] != 0x02) throw new FormatException("der");
        int sl = der[i++]; var s = new BigInteger(der[i..(i + sl)], isUnsigned: true, isBigEndian: true);
        return (r, s);
    }
}
