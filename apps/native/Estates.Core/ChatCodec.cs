// Estates.Core/ChatCodec.cs — the ESTATES chat wire frame, combining BOTH primitives
// exactly as specified: the message is broadcast-encrypted ONCE under the GB 2623780 B
// key-graph root (Broadcast), and each member's leaf key is delivered by 2-person ECDH
// (Cipher.EcdhSeal — the sender's OWN key ↔ that member's wallet pubkey; NO ECIES, no
// ephemeral key). A non-member has no leaf key and cannot reach the message key; ciphertext
// only on the wire. Total: hostile bytes → null.
using System.Text;
using System.Text.Json;

namespace Estates.Core;

public static class ChatCodec
{
    private static readonly byte[] LeafAad = Encoding.ASCII.GetBytes("chat/leaf/v1");

    /// <summary>Seal `text` to `recipientPubs` (their compressed wallet pubkeys) as a full chat
    /// frame, signed by YOUR key `myWalletPriv` (used for the 2-person ECDH leaf delivery — the
    /// recipients ECDH with your `from` pubkey). Returns null with no recipients.</summary>
    public static byte[]? Seal(byte[] myWalletPriv, IReadOnlyList<byte[]> recipientPubs, string text)
    {
        if (recipientPubs.Count == 0) return null;
        byte[] myWalletPub = Secp256k1.PublicKey(myWalletPriv);
        var graph = Broadcast.Build(recipientPubs.Count);
        var msg = (Cipher.SealedMessage.Symmetric)graph.EncryptMessage(Encoding.UTF8.GetBytes(text));
        var items = graph.EncryptedDataItems();

        var leaf = new List<object>();
        for (int i = 0; i < recipientPubs.Count; i++)
        {
            byte[] leafKey = graph.MemberLeafKey(i);
            var sealed_ = Cipher.EcdhSeal(myWalletPriv, recipientPubs[i], leafKey, LeafAad);
            leaf.Add(new Dictionary<string, object>
            {
                ["pub"] = Tx.ToHex(recipientPubs[i]), ["m"] = i,
                ["n"] = Tx.ToHex(sealed_.Nonce), ["ct"] = Tx.ToHex(sealed_.Bytes),
            });
        }

        var frame = new Dictionary<string, object>
        {
            ["kind"] = "chat",
            ["from"] = Tx.ToHex(myWalletPub),
            ["leaves"] = graph.Leaves,
            ["msg"] = new Dictionary<string, object> { ["n"] = Tx.ToHex(msg.Nonce), ["ct"] = Tx.ToHex(msg.Bytes) },
            ["items"] = items.Select(it => (object)new Dictionary<string, object>
            {
                ["node"] = it.Node, ["parent"] = it.Parent,
                ["n"] = Tx.ToHex(it.WrappedParentKey.Nonce), ["w"] = Tx.ToHex(it.WrappedParentKey.Bytes),
            }).ToList(),
            ["leaf"] = leaf,
        };
        return Encoding.UTF8.GetBytes(JsonSerializer.Serialize(frame));
    }

    /// <summary>Open a chat frame addressed to me (my wallet key). Returns (fromPubHex,
    /// text) or null. Total: never throws on hostile bytes.</summary>
    public static (string from, string text)? Open(byte[] frame, byte[] myPriv, byte[] myWalletPub)
    {
        try
        {
            using var doc = JsonDocument.Parse(frame);
            var e = doc.RootElement;
            if (e.ValueKind != JsonValueKind.Object) return null;
            if (!e.TryGetProperty("kind", out var k) || k.GetString() != "chat") return null;
            if (!e.TryGetProperty("from", out var f) || f.ValueKind != JsonValueKind.String) return null;
            int leaves = e.GetProperty("leaves").GetInt32();
            string myPubHex = Tx.ToHex(myWalletPub);

            // find my leaf-key delivery (2-person ECDH: my key ↔ the sender's `from` key)
            byte[] fromPub = Tx.FromHex(f.GetString()!);
            int member = -1; Cipher.EcdhSealed? mine = null;
            foreach (var l in e.GetProperty("leaf").EnumerateArray())
            {
                if (l.GetProperty("pub").GetString() != myPubHex) continue;
                member = l.GetProperty("m").GetInt32();
                mine = new Cipher.EcdhSealed(Tx.FromHex(l.GetProperty("n").GetString()!), Tx.FromHex(l.GetProperty("ct").GetString()!));
                break;
            }
            if (mine is null) return null;                            // not a recipient
            byte[]? leafKey = Cipher.EcdhOpen(myPriv, fromPub, mine, LeafAad);
            if (leafKey is null) return null;

            // rebuild the published items + sealed message
            var items = new List<Broadcast.DataItem>();
            foreach (var it in e.GetProperty("items").EnumerateArray())
            {
                items.Add(new Broadcast.DataItem(
                    it.GetProperty("node").GetInt32(), it.GetProperty("parent").GetInt32(),
                    new Cipher.WrappedKey(Tx.FromHex(it.GetProperty("n").GetString()!), Tx.FromHex(it.GetProperty("w").GetString()!))));
            }
            var m = e.GetProperty("msg");
            var sealed_ = new Cipher.SealedMessage.Symmetric(Tx.FromHex(m.GetProperty("n").GetString()!), Tx.FromHex(m.GetProperty("ct").GetString()!));

            byte[]? pt = Broadcast.MemberDecrypt(member, leaves, leafKey, items, sealed_);
            if (pt is null) return null;
            return (f.GetString()!, Encoding.UTF8.GetString(pt));
        }
        catch { return null; }
    }
}
