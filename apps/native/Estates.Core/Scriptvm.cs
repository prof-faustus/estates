// Estates.Core/Scriptvm.cs — native BIP-143 sighash + secp256k1 ECDSA verify, the
// OP_CHECKSIG core, byte-for-byte with @estates/scriptvm. Lets the native exe
// verify the SAME transaction-input signatures the web produces. secp256k1 via
// BouncyCastle (the reference curve real Bitcoin uses).
using System.Globalization;
using System.Security.Cryptography;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Math;

namespace Estates.Core;

public static class Scriptvm
{
    private static readonly SecP256K1 K = new();
    private sealed class SecP256K1
    {
        public readonly ECDomainParameters Dom;
        public SecP256K1() { var p = SecNamedCurves.GetByName("secp256k1"); Dom = new ECDomainParameters(p.Curve, p.G, p.N, p.H); }
    }

    private static void U32Le(List<byte> o, long n) { for (int i = 0; i < 4; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    private static void U64Le(List<byte> o, long n) { for (int i = 0; i < 8; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    private static void Varint(List<byte> o, long n)
    {
        if (n < 0xfd) o.Add((byte)n);
        else if (n <= 0xffff) { o.Add(0xfd); o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); }
        else if (n <= 0xffffffff) { o.Add(0xfe); U32Le(o, n); }
        else { o.Add(0xff); U64Le(o, n); }
    }
    private static byte[] RevTxid(string txid) { var b = Tx.FromHex(txid); Array.Reverse(b); return b; }

    /// <summary>BIP-143 sighash for input `i` spending `prevout` (script+value)
    /// under `hashType`. Mirrors @estates/scriptvm.sighash exactly.</summary>
    public static byte[] Sighash(NativeTx tx, int i, byte[] prevoutScript, long prevoutValue, long hashType)
    {
        var hp = new List<byte>(); foreach (var inp in tx.Inputs) { hp.AddRange(RevTxid(inp.PrevTxid)); U32Le(hp, inp.PrevVout); }
        var hashPrevouts = Tx.Hash256(hp.ToArray());
        var hs = new List<byte>(); foreach (var inp in tx.Inputs) U32Le(hs, inp.Sequence);
        var hashSequence = Tx.Hash256(hs.ToArray());
        var ho = new List<byte>(); foreach (var o in tx.Outputs) { U64Le(ho, o.Value); Varint(ho, o.Script.Length); ho.AddRange(o.Script); }
        var hashOutputs = Tx.Hash256(ho.ToArray());

        var inI = tx.Inputs[i];
        var pre = new List<byte>(256);
        U32Le(pre, tx.Version);
        pre.AddRange(hashPrevouts); pre.AddRange(hashSequence);
        pre.AddRange(RevTxid(inI.PrevTxid)); U32Le(pre, inI.PrevVout);
        Varint(pre, prevoutScript.Length); pre.AddRange(prevoutScript);
        U64Le(pre, prevoutValue); U32Le(pre, inI.Sequence);
        pre.AddRange(hashOutputs); U32Le(pre, tx.LockTime); U32Le(pre, hashType);
        return Tx.Hash256(pre.ToArray());
    }

    /// <summary>Verify a DER ECDSA signature over `msgHash` by compressed pubkey
    /// `pubHex`. Total: false on any malformed input, never throws.</summary>
    public static bool VerifyEcdsaDer(byte[] der, byte[] msgHash, string pubHex)
    {
        try
        {
            var seq = (Asn1Sequence)Asn1Object.FromByteArray(der);
            var r = ((DerInteger)seq[0]).Value;
            var s = ((DerInteger)seq[1]).Value;
            var point = K.Dom.Curve.DecodePoint(Tx.FromHex(pubHex));
            var pub = new ECPublicKeyParameters(point, K.Dom);
            var signer = new ECDsaSigner();
            signer.Init(false, pub);
            return signer.VerifySignature(msgHash, r, s);
        }
        catch { return false; }
    }

    /// <summary>OP_CHECKSIG: the scriptSig signature is DER ‖ hashType(1). Compute
    /// the BIP-143 sighash for this input/prevout and ECDSA-verify it.</summary>
    public static bool CheckSig(NativeTx tx, int i, byte[] prevoutScript, long prevoutValue, byte[] sigWithHashType, string pubHex)
    {
        if (sigWithHashType.Length < 9) return false;
        long hashType = sigWithHashType[^1];
        var der = sigWithHashType[..^1];
        var h = Sighash(tx, i, prevoutScript, prevoutValue, hashType);
        return VerifyEcdsaDer(der, h, pubHex);
    }
}
