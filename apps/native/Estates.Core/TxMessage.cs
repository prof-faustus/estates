// Estates.Core/TxMessage.cs — THE RULE, made concrete: every communication is a Bitcoin transaction.
// An application message (chat, move, presence, deal, …) is encoded into a transaction's carrier output
// as: the typed protocol header (TxProtocol) + the sender's PER-MESSAGE public key + an ECDH-encrypted
// payload. The encryption key is a FRESH per-message ECDH key from the KeyRing — never reused. The
// recipient decrypts with its own key. The very same transaction bytes are then sent IP-to-IP directly
// to the other player AND broadcast to the mining nodes (dual propagation — see TxTransport).
//
// Carrier payload layout (after the 6-byte TxProtocol header):
//   senderMsgPub(33) ‖ nonceLen(1) ‖ nonce(nonceLen) ‖ ciphertext
namespace Estates.Core;

public static class TxMessage
{
    /// <summary>Seal a message into a typed, encrypted carrier. `senderMsgPriv` is a fresh per-message
    /// key (KeyRing.MessagePriv); the AES-256-GCM key is the ECDH of it with the recipient's pubkey.</summary>
    public static byte[] SealCarrier(byte[] senderMsgPriv, byte[] recipientPub, TxType type, byte[] plaintext)
    {
        byte[] senderMsgPub = Secp256k1.PublicKey(senderMsgPriv);
        var s = Cipher.EcdhSeal(senderMsgPriv, recipientPub, plaintext, senderMsgPub);   // aad binds the sender key
        var payload = new List<byte>(33 + 1 + s.Nonce.Length + s.Bytes.Length);
        payload.AddRange(senderMsgPub);
        payload.Add((byte)s.Nonce.Length);
        payload.AddRange(s.Nonce);
        payload.AddRange(s.Bytes);
        return TxProtocol.Stamp(type, payload.ToArray());
    }

    /// <summary>TOTAL: open a carrier with the recipient's private key. null if it is not an ESTATES
    /// typed message, is malformed, or is not for this recipient (decryption fails closed).</summary>
    public static (TxType type, byte[] senderMsgPub, byte[] plaintext)? OpenCarrier(byte[] carrier, byte[] recipientPriv)
    {
        var h = TxProtocol.Read(carrier);
        if (h is null) return null;
        var p = h.Value.payload;
        if (p.Length < 33 + 1) return null;
        var senderPub = p[..33];
        int nlen = p[33];
        if (nlen < 1 || 34 + nlen > p.Length) return null;
        var nonce = p[34..(34 + nlen)];
        var ct = p[(34 + nlen)..];
        var pt = Cipher.EcdhOpen(recipientPriv, senderPub, new Cipher.EcdhSealed(nonce, ct), senderPub);
        return pt is null ? null : (h.Value.type, senderPub, pt);
    }
}
