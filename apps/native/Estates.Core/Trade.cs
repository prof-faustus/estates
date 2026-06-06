// Estates.Core/Trade.cs — TRADE (#13): an ATOMIC SWAP of two NFTs in ONE transaction. Both NFTs
// change hands or neither does — there is no trusted intermediary and no half-completed trade. The
// single tx spends both NFTs (input 0 = A's, input 1 = B's) and produces both re-sealed to the new
// owner (output 0 = A's NFT to B, output 1 = B's NFT to A). Each party signs ONLY their own input,
// so the swap is valid only when both have signed — atomicity by construction. Re-sealing uses
// ECDH-with-an-AES-key (no ECIES): the prior owner's copy is dead, only the new owner can decrypt.
namespace Estates.Core;

public static class Trade
{
    private const long SighashAllForkId = 0x41;
    private static readonly byte[] CardAad = "estates/card-nft/v1"u8.ToArray();   // matches OnChainActions

    private static byte[] Concat(params byte[][] xs) { var o = new List<byte>(); foreach (var x in xs) o.AddRange(x); return o.ToArray(); }
    private static byte[] Push(byte[] d)
    {
        if (d.Length < 0x4c) return Concat(new[] { (byte)d.Length }, d);
        if (d.Length <= 0xff) return Concat(new byte[] { 0x4c, (byte)d.Length }, d);
        throw new ArgumentException("push too large for a scriptSig element");
    }

    /// <summary>Re-seal `face` to `newOwnerPub` using `senderPriv` (the current owner), as the
    /// NFT-TRANSFER (#5) carrier payload: header ‖ senderPub(33) ‖ nonce(12) ‖ ciphertext.</summary>
    public static byte[] Reseal(byte[] senderPriv, byte[] newOwnerPub, byte[] face)
    {
        byte[] senderPub = Secp256k1.PublicKey(senderPriv);
        var ct = Cipher.EcdhSeal(senderPriv, newOwnerPub, face, CardAad);
        return TxProtocol.Stamp(TxType.NftTransfer, Concat(senderPub, ct.Nonce, ct.Bytes));
    }

    /// <summary>Build the fully-signed atomic swap: A's NFT → B and B's NFT → A in one transaction.
    /// `aNft`/`bNft` carry their NFT carrier `Script` (the prevout). Each side signs its own input.</summary>
    public static NativeTx BuildSwap(
        Coin aNft, byte[] aFace, byte[] aPriv,
        Coin bNft, byte[] bFace, byte[] bPriv)
    {
        byte[] aPub = Secp256k1.PublicKey(aPriv), bPub = Secp256k1.PublicKey(bPriv);
        var outs = new[]
        {
            new TxOutputN(1, OnChainActions.CarrierScript(Reseal(aPriv, bPub, aFace), Recovery.Hash160(bPub))), // A's NFT → B
            new TxOutputN(1, OnChainActions.CarrierScript(Reseal(bPriv, aPub, bFace), Recovery.Hash160(aPub))), // B's NFT → A
        };
        var unsigned = new NativeTx(2, new[]
        {
            new TxInputN(aNft.Txid, aNft.Vout, Array.Empty<byte>(), 0xffffffff),
            new TxInputN(bNft.Txid, bNft.Vout, Array.Empty<byte>(), 0xffffffff),
        }, outs, 0);
        var inA = SignInput(unsigned, 0, aNft, aPriv);
        var inB = SignInput(unsigned, 1, bNft, bPriv);
        return new NativeTx(2, new[] { inA, inB }, outs, 0);
    }

    /// <summary>Verify both inputs of a swap are validly signed by their respective owners (the proof
    /// that the atomic swap is spend-valid: only both signatures together make it so).</summary>
    public static bool VerifySwap(NativeTx swap, Coin aNft, byte[] aOwnerPub, Coin bNft, byte[] bOwnerPub)
    {
        if (swap.Inputs.Count != 2) return false;
        return CheckInput(swap, 0, aNft, aOwnerPub) && CheckInput(swap, 1, bNft, bOwnerPub);
    }

    private static TxInputN SignInput(NativeTx tx, int i, Coin coin, byte[] priv)
    {
        byte[] pub = Secp256k1.PublicKey(priv);
        byte[] prevScript = coin.Script ?? Recovery.P2pkh(Recovery.Hash160(pub));
        byte[] sighash = Scriptvm.Sighash(tx, i, prevScript, coin.Sats, SighashAllForkId);
        byte[] der = EcdsaSign.SignPrehashDer(priv, sighash);
        byte[] sig = Concat(der, new byte[] { (byte)SighashAllForkId });
        return tx.Inputs[i] with { ScriptSig = Concat(Push(sig), Push(pub)) };
    }

    private static bool CheckInput(NativeTx tx, int i, Coin coin, byte[] ownerPub)
    {
        byte[] prevScript = coin.Script ?? Recovery.P2pkh(Recovery.Hash160(ownerPub));
        byte[] ss = tx.Inputs[i].ScriptSig;
        // scriptSig = push(sig) push(pub); read the two elements
        int p = 0;
        byte[] Read() { int n = ss[p++]; if (n == 0x4c) n = ss[p++]; var b = ss[p..(p + n)]; p += n; return b; }
        byte[] sig = Read(); byte[] pub = Read();
        return Scriptvm.CheckSig(tx, i, prevScript, coin.Sats, sig, Tx.ToHex(pub));
    }
}
