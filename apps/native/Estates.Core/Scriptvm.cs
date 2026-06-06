// Estates.Core/Scriptvm.cs — BSV SIGHASH_FORKID preimage + secp256k1 ECDSA verify (OP_CHECKSIG),
// LIBRARY-FREE: verification is the in-tree Secp256k1 (via EcdsaSign); hashing is Microsoft .NET.
// NO third-party library. Fail-closed: only SIGHASH_ALL|FORKID (0x41) is accepted.
using System.Globalization;
using System.Security.Cryptography;

namespace Estates.Core;

public static class Scriptvm
{
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
        try { return EcdsaSign.VerifyDerPrehash(Tx.FromHex(pubHex), msgHash, der); }
        catch { return false; }
    }

    /// <summary>OP_CHECKSIG: the scriptSig signature is DER ‖ hashType(1). Compute
    /// the BIP-143 sighash for this input/prevout and ECDSA-verify it.</summary>
    public static bool CheckSig(NativeTx tx, int i, byte[] prevoutScript, long prevoutValue, byte[] sigWithHashType, string pubHex)
    {
        if (sigWithHashType.Length < 9) return false;
        long hashType = sigWithHashType[^1];
        if (hashType != 0x41) return false;   // fail-closed: only SIGHASH_ALL|FORKID (0x41) is supported
        var der = sigWithHashType[..^1];
        var h = Sighash(tx, i, prevoutScript, prevoutValue, hashType);
        return VerifyEcdsaDer(der, h, pubHex);
    }
}
