// Estates.Core/Recovery.cs — the "no sat is ever lost" guarantee, built on real BSV
// transactions. Funds a player/bot commits sit in a 2-of-2 (the funder + the
// counterparty). BEFORE any sat is at risk, BOTH parties pre-sign an nLockTime REFUND
// that returns 100% of the stake to the FUNDER and becomes valid after a future
// locktime. So if the counterparty vanishes (closes / never co-operates), the funder
// broadcasts the refund after the locktime and recovers everything — unilaterally.
//
// Timing is the transaction's nLockTime + input nSequence ONLY (no CLTV/CSV). Sighash is the
// BSV FORKID sighash (Scriptvm.Sighash); signatures are secp256k1 ECDSA (EcdsaSign) — Bitcoin BSV.
using System.Security.Cryptography;

namespace Estates.Core;

public static class Recovery
{
    private const byte OP_0 = 0x00, OP_2 = 0x52, OP_DUP = 0x76, OP_HASH160 = 0xa9,
                       OP_EQUALVERIFY = 0x88, OP_CHECKSIG = 0xac, OP_CHECKMULTISIG = 0xae;
    public const long SighashAllForkId = 0x41;          // BSV: SIGHASH_ALL | SIGHASH_FORKID
    private const long EnableLockTimeSeq = 0xfffffffe;  // < 0xffffffff so nLockTime is active

    private static byte[] PushData(byte[] d)
    {
        if (d.Length < 0x4c) { var o = new byte[d.Length + 1]; o[0] = (byte)d.Length; Array.Copy(d, 0, o, 1, d.Length); return o; }
        throw new ArgumentException("pushdata > 75 not needed here");
    }

    /// <summary>The 2-of-2 locking script: OP_2 &lt;pubA&gt; &lt;pubB&gt; OP_2 OP_CHECKMULTISIG.
    /// Pubkeys are 33-byte compressed; order is fixed (sigs must be supplied in this order).</summary>
    public static byte[] Multisig2of2(byte[] pubA, byte[] pubB)
    {
        if (pubA.Length != 33 || pubB.Length != 33) throw new ArgumentException("compressed pubkeys (33 bytes) required");
        var o = new List<byte> { OP_2 };
        o.AddRange(PushData(pubA)); o.AddRange(PushData(pubB));
        o.Add(OP_2); o.Add(OP_CHECKMULTISIG);
        return o.ToArray();
    }

    /// <summary>A standard P2PKH locking script for the refund output (funds back to the funder).</summary>
    public static byte[] P2pkh(byte[] pkh20)
    {
        if (pkh20.Length != 20) throw new ArgumentException("pkh must be 20 bytes");
        var o = new List<byte> { OP_DUP, OP_HASH160 };
        o.AddRange(PushData(pkh20)); o.Add(OP_EQUALVERIFY); o.Add(OP_CHECKSIG);
        return o.ToArray();
    }

    /// <summary>hash160 = ripemd160(sha256(pub)) — the funder's address for the refund.</summary>
    public static byte[] Hash160(byte[] pub) => Ripemd160.Hash(SHA256.HashData(pub));   // in-tree, no library

    /// <summary>Build the UNSIGNED nLockTime refund: spends the 2-of-2 funding output back to
    /// the funder's P2PKH, valued (stake − fee), valid only at/after `lockTime`.</summary>
    public static NativeTx BuildRefund(string fundingTxid, long fundingVout, long stakeSats, long feeSats, byte[] funderPub, long lockTime)
    {
        long refundValue = stakeSats - feeSats;
        if (refundValue <= 0) throw new ArgumentException("stake must exceed the fee");
        var input = new TxInputN(fundingTxid, fundingVout, Array.Empty<byte>(), EnableLockTimeSeq);
        var output = new TxOutputN(refundValue, P2pkh(Hash160(funderPub)));
        return new NativeTx(2, new[] { input }, new[] { output }, lockTime);
    }

    /// <summary>One party's DER signature (with the BSV hashtype byte appended) over the
    /// refund's single input, against the 2-of-2 funding script.</summary>
    public static byte[] SignRefundInput(NativeTx refund, byte[] multisigScript, long stakeSats, byte[] priv)
    {
        byte[] sighash = Scriptvm.Sighash(refund, 0, multisigScript, stakeSats, SighashAllForkId);
        byte[] der = EcdsaSign.SignPrehashDer(priv, sighash);
        var sig = new byte[der.Length + 1];
        Array.Copy(der, sig, der.Length);
        sig[^1] = (byte)SighashAllForkId;
        return sig;
    }

    /// <summary>Assemble the spending scriptSig for the 2-of-2 input: OP_0 &lt;sigA&gt; &lt;sigB&gt;
    /// (the leading OP_0 is CHECKMULTISIG's well-known dummy). Returns the completed refund.</summary>
    public static NativeTx CompleteRefund(NativeTx refund, byte[] sigA, byte[] sigB)
    {
        var ss = new List<byte> { OP_0 };
        ss.AddRange(PushData(sigA)); ss.AddRange(PushData(sigB));
        var input = refund.Inputs[0] with { ScriptSig = ss.ToArray() };
        return new NativeTx(refund.Version, new[] { input }, refund.Outputs, refund.LockTime);
    }

    /// <summary>Verify BOTH signatures of a refund against the 2-of-2 script — the proof the
    /// funder holds a valid, broadcastable, 100%-recovery refund before risking a sat.</summary>
    public static bool VerifyRefund(NativeTx refund, byte[] multisigScript, long stakeSats, byte[] pubA, byte[] sigAWithType, byte[] pubB, byte[] sigBWithType)
    {
        byte[] sighash = Scriptvm.Sighash(refund, 0, multisigScript, stakeSats, SighashAllForkId);
        byte[] derA = sigAWithType[..^1];
        byte[] derB = sigBWithType[..^1];
        return Scriptvm.VerifyEcdsaDer(derA, sighash, Tx.ToHex(pubA))
            && Scriptvm.VerifyEcdsaDer(derB, sighash, Tx.ToHex(pubB));
    }
}
