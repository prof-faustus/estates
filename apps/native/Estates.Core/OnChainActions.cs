// Estates.Core/OnChainActions.cs — EVERYTHING IS AN ON-CHAIN TRANSACTION. Every game/system action
// becomes a real, signed BSV transaction built ENTIRELY in-process from the standalone wallet (no
// node, no RPC): a move, a deal, a chat line, a keep-alive, a card mint, a card transfer. The
// resulting raw tx is dual-propagated (broadcast to the BSV network via the in-client node AND sent
// over the IP-to-IP game links). Maximizing on-chain activity is the goal, not minimizing it.
//
// Cards/deeds are TRUE ENCRYPTED NFTs: the face is ECDH+AES-sealed to the owner (NO ECDH+AES) and rides
// on-chain in a 1-sat data output. A transfer SPENDS the old NFT outpoint and RE-SEALS the face to the
// NEW owner —
// so the prior owner's copy is on-chain dead and only the new owner can decrypt it (digital scarcity:
// Alice→Bob ⇒ Bob has it, Alice does not). No OP_RETURN — state is pushdata + OP_DROP over a P2PKH.
using System.Security.Cryptography;

namespace Estates.Core;

public static class OnChainActions
{
    private const byte OP_DROP = 0x75, OP_DUP = 0x76, OP_HASH160 = 0xa9, OP_EQUALVERIFY = 0x88, OP_CHECKSIG = 0xac;
    private static readonly byte[] CardAad = "estates/card-nft/v1"u8.ToArray();
    private static readonly byte[] ChatAad = "estates/chat/v1"u8.ToArray();

    private static byte[] Push(byte[] d)
    {
        var o = new List<byte>();
        if (d.Length < 0x4c) o.Add((byte)d.Length);
        else if (d.Length <= 0xff) { o.Add(0x4c); o.Add((byte)d.Length); }
        else if (d.Length <= 0xffff) { o.Add(0x4d); o.Add((byte)(d.Length & 0xff)); o.Add((byte)((d.Length >> 8) & 0xff)); }
        else { o.Add(0x4e); for (int i = 0; i < 4; i++) o.Add((byte)((d.Length >> (8 * i)) & 0xff)); }
        o.AddRange(d); return o.ToArray();
    }
    private static byte[] P2pkh(byte[] pkh20)
    {
        var o = new List<byte> { OP_DUP, OP_HASH160 }; o.AddRange(Push(pkh20)); o.Add(OP_EQUALVERIFY); o.Add(OP_CHECKSIG);
        return o.ToArray();
    }
    /// <summary>A 1-sat data-carrier output: &lt;data&gt; OP_DROP P2PKH(owner) — state on-chain, still
    /// spendable, NO OP_RETURN. Used for moves, chat, deals, keep-alives, and NFTs (owner = holder).</summary>
    public static byte[] CarrierScript(byte[] data, byte[] ownerPkh)
    {
        var o = new List<byte>(); o.AddRange(Push(data)); o.Add(OP_DROP); o.AddRange(P2pkh(ownerPkh));
        return o.ToArray();
    }

    /// <summary>Build a TYPED transaction (TxProtocol): a 1-sat marker output carrying the type's
    /// self-identifying header ‖ payload, funded by the wallet. The header makes the protocol number
    /// extractable as a layer; each TYPE is a distinct template via its own payload + smart contract.</summary>
    public static StandaloneWallet.BuiltTx Typed(StandaloneWallet w, TxType type, byte[] payload, long feeSats)
    {
        byte[] selfPkh = Recovery.Hash160(w.ChildPub(0));
        return w.BuildAndSign(new[] { new TxOutputN(1, CarrierScript(TxProtocol.Stamp(type, payload), selfPkh)) }, feeSats, 0);
    }

    /// <summary>KEEPALIVE (#8) — a presence heartbeat, itself a real transaction.</summary>
    public static StandaloneWallet.BuiltTx KeepAlive(StandaloneWallet w, long feeSats) => Typed(w, TxType.KeepAlive, Array.Empty<byte>(), feeSats);
    /// <summary>MOVE (#9) — a game move.</summary>
    public static StandaloneWallet.BuiltTx Move(StandaloneWallet w, byte[] commitment, long feeSats) => Typed(w, TxType.Move, commitment, feeSats);
    /// <summary>COMMITMENT (#6) — a mental-poker shuffle / dice beacon commit.</summary>
    public static StandaloneWallet.BuiltTx Commit(StandaloneWallet w, byte[] commitHash, long feeSats) => Typed(w, TxType.Commitment, commitHash, feeSats);
    /// <summary>REVEAL (#7) — opening a prior commitment.</summary>
    public static StandaloneWallet.BuiltTx Reveal(StandaloneWallet w, byte[] secret, long feeSats) => Typed(w, TxType.Reveal, secret, feeSats);

    /// <summary>Read the protocol layer off a typed marker's carrier data: which type is this tx?</summary>
    public static (TxType type, byte version, byte[] payload)? ReadType(byte[] carrierData) => TxProtocol.Read(carrierData);

    public sealed record CardMint(StandaloneWallet.BuiltTx Tx, byte[] NftData);

    /// <summary>Mint a card/deed as a TRUE ENCRYPTED NFT to `recipientPub`: ECDH+AES-seal the face, carry
    /// it on-chain in a 1-sat NFT output owned by the recipient. Returns the tx + the on-chain NFT data.</summary>
    public static CardMint MintCard(StandaloneWallet w, byte[] face, byte[] recipientPub, long feeSats)
    {
        byte[] data = SealFace(w.ChildPriv(0), recipientPub, face);
        byte[] marker = TxProtocol.Stamp(TxType.NftMint, data);
        var tx = w.BuildAndSign(new[] { new TxOutputN(1, CarrierScript(marker, Recovery.Hash160(recipientPub))) }, feeSats, 0);
        return new CardMint(tx, data);
    }

    /// <summary>Transfer a card NFT with DIGITAL SCARCITY: spend the old NFT outpoint (`nftCoin`) and
    /// RE-SEAL the face to `newOwnerPub`. The old encryption/outpoint is dead; only the new owner can
    /// open the result. Funded for the fee from the wallet's other coins.</summary>
    public static CardMint TransferCard(StandaloneWallet w, Coin nftCoin, byte[] face, byte[] newOwnerPub, long feeSats)
    {
        byte[] data = SealFace(w.ChildPriv(nftCoin.AddrIndex), newOwnerPub, face);
        byte[] marker = TxProtocol.Stamp(TxType.NftTransfer, data);
        var tx = w.BuildWithForcedInput(nftCoin, new[] { new TxOutputN(1, CarrierScript(marker, Recovery.Hash160(newOwnerPub))) }, feeSats, 0);
        return new CardMint(tx, data);
    }

    /// <summary>Open a card NFT you own: ECDH+AES-decrypt the on-chain face with your private key. Returns
    /// null for anyone who is not the sealed owner (the scarcity guarantee).</summary>
    public static byte[]? OpenCard(byte[] ownerPriv, byte[] nftData)
    {
        if (nftData.Length < 33 + 12) return null;
        return Cipher.EcdhOpen(ownerPriv, nftData[..33], new Cipher.EcdhSealed(nftData[33..45], nftData[45..]), CardAad);
    }

    /// <summary>Encrypted ON-CHAIN chat: ECDH+AES-seal the message to `recipientPub` and carry it on-chain
    /// (a real tx), not over the connection. Permanent + verifiable; only the recipient can read it.</summary>
    public static StandaloneWallet.BuiltTx Chat(StandaloneWallet w, byte[] recipientPub, string message, long feeSats)
    {
        byte[] senderPriv = w.ChildPriv(0); byte[] senderPub = Secp256k1.PublicKey(senderPriv);
        var ct = Cipher.EcdhSeal(senderPriv, recipientPub, System.Text.Encoding.UTF8.GetBytes(message), ChatAad);
        byte[] data = TxProtocol.Stamp(TxType.Chat2P, Concat(Concat(senderPub, ct.Nonce), ct.Bytes));
        byte[] selfPkh = Recovery.Hash160(w.ChildPub(0));
        return w.BuildAndSign(new[] { new TxOutputN(1, CarrierScript(data, selfPkh)) }, feeSats, 0);
    }

    /// <summary>Read an encrypted on-chain chat message addressed to you (null if not yours).</summary>
    public static string? OpenChat(byte[] recipientPriv, byte[] chatData)
    {
        var hdr = TxProtocol.Read(chatData);
        if (hdr is null || hdr.Value.type != TxType.Chat2P) return null;
        byte[] p = hdr.Value.payload;
        if (p.Length < 45) return null;
        byte[]? pt = Cipher.EcdhOpen(recipientPriv, p[..33], new Cipher.EcdhSealed(p[33..45], p[45..]), ChatAad);
        return pt is null ? null : System.Text.Encoding.UTF8.GetString(pt);
    }

    // NFT/chat data layout: senderPub(33) ‖ nonce(12) ‖ ciphertext+tag. The recipient ECDHs their
    // own key with senderPub to get the AES key — ECDH only, no ECDH+AES, no ephemeral.
    private static byte[] SealFace(byte[] senderPriv, byte[] recipientPub, byte[] face)
    {
        byte[] senderPub = Secp256k1.PublicKey(senderPriv);
        var ct = Cipher.EcdhSeal(senderPriv, recipientPub, face, CardAad);
        return Concat(Concat(senderPub, ct.Nonce), ct.Bytes);
    }
    private static byte[] Concat(byte[] a, byte[] b) { var o = new byte[a.Length + b.Length]; Array.Copy(a, o, a.Length); Array.Copy(b, 0, o, a.Length, b.Length); return o; }
}
