// Estates.Core/Multisig.cs — the 2-of-2 used to fund a bot. The human (Alice) funds a 2-of-2 output
// locked to {Alice, bot(Bob)}; the human keeps control. On close the bot signs and signals Alice, and
// Alice spends the 2-of-2 to reclaim 100% of the funds (refund-to-funder). Both signatures are required,
// so neither side can move the money alone. FORKID sighash, low-S ECDSA, in-tree only.
namespace Estates.Core;

public static class Multisig
{
    private const long ForkId = 0x41;

    /// <summary>2-of-2 locking script: OP_2 &lt;pubA&gt; &lt;pubB&gt; OP_2 OP_CHECKMULTISIG.</summary>
    public static byte[] Lock2of2(byte[] pubA, byte[] pubB)
    {
        var o = new List<byte> { 0x52 };           // OP_2
        Push(o, pubA); Push(o, pubB);
        o.Add(0x52); o.Add(0xae);                  // OP_2 OP_CHECKMULTISIG
        return o.ToArray();
    }

    /// <summary>One party's signature (DER ‖ FORKID hashtype) for spending the 2-of-2 at input `i`.</summary>
    public static byte[] Sign(NativeTx tx, int i, byte[] lockScript, long value, byte[] priv)
    {
        byte[] sh = Scriptvm.Sighash(tx, i, lockScript, value, ForkId);
        byte[] der = EcdsaSign.SignPrehashDer(priv, sh);
        var s = new byte[der.Length + 1]; System.Array.Copy(der, s, der.Length); s[^1] = (byte)ForkId;
        return s;
    }

    /// <summary>Verify both signatures against the 2-of-2 (both must be valid). This is what a node /
    /// the recipient checks before accepting the reclaim/settlement spend.</summary>
    public static bool Verify2of2(NativeTx tx, int i, byte[] lockScript, long value, byte[] sigA, byte[] sigB, byte[] pubA, byte[] pubB)
    {
        if (sigA.Length < 2 || sigB.Length < 2) return false;
        byte[] sh = Scriptvm.Sighash(tx, i, lockScript, value, ForkId);
        return EcdsaSign.VerifyDerPrehash(pubA, sh, sigA[..^1]) && EcdsaSign.VerifyDerPrehash(pubB, sh, sigB[..^1]);
    }

    /// <summary>The CHECKMULTISIG unlocking script: OP_0 ‖ &lt;sigA&gt; ‖ &lt;sigB&gt; (dummy for the
    /// off-by-one, then the two signatures in pubkey order).</summary>
    public static byte[] Unlock2of2(byte[] sigA, byte[] sigB)
    {
        var o = new List<byte> { 0x00 };           // OP_0 (CHECKMULTISIG dummy)
        Push(o, sigA); Push(o, sigB);
        return o.ToArray();
    }

    private static void Push(List<byte> o, byte[] d)
    {
        if (d.Length < 0x4c) o.Add((byte)d.Length);
        else if (d.Length <= 0xff) { o.Add(0x4c); o.Add((byte)d.Length); }
        else { o.Add(0x4d); o.Add((byte)(d.Length & 0xff)); o.Add((byte)(d.Length >> 8)); }
        o.AddRange(d);
    }
}
