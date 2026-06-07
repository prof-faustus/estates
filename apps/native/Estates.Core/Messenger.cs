// Estates.Core/Messenger.cs — the full-messenger BACKEND (WhatsApp/Telegram/Signal-class semantics):
// contacts (identity cards), 1:1 + group conversations, message history, and the message KINDS a
// modern messenger has — text, reply, reaction, edit, delete, read-receipt, typing, media. Each
// message is serialized here and carried on-chain ENCRYPTED as a typed transaction (CHAT-2P #2 for
// 1:1, CHAT-GROUP #3 for groups — see OnChainActions). This module is the model + apply-logic; the
// UI binds to it. Encryption is ECDH-with-an-AES-key / the broadcast key-graph.
using System.Text;

namespace Estates.Core;

public enum ChatKind : byte { Text = 0, Reply = 1, Reaction = 2, Edit = 3, Delete = 4, ReadReceipt = 5, Typing = 6, Media = 7 }

/// <summary>One messenger message. `RefId` targets another message (reply/reaction/edit/delete/receipt).
/// `Media` holds an attachment reference (e.g. an on-chain media NFT outpoint) for Media messages.</summary>
public sealed record ChatMessage(string Id, ChatKind Kind, string FromPub, long TimeUnix, string Text, string? RefId, string? Media)
{
    public bool Deleted { get; set; }
    public string? EditedText { get; set; }
    public readonly Dictionary<string, string> Reactions = new();   // fromPub -> emoji
    public readonly HashSet<string> ReadBy = new();                 // pubs that have read it
    public string Display => Deleted ? "(deleted)" : EditedText ?? Text;
}

/// <summary>A conversation (1:1 or group) with ordered history.</summary>
public sealed class Conversation
{
    public string Id { get; }
    public bool IsGroup { get; }
    public List<string> Participants { get; }            // member pubkeys (hex)
    public List<ChatMessage> History { get; } = new();
    private readonly Dictionary<string, ChatMessage> _byId = new();
    public Conversation(string id, bool group, IEnumerable<string> participants) { Id = id; IsGroup = group; Participants = participants.ToList(); }

    /// <summary>Apply an incoming/outgoing message, folding edits/deletes/reactions/receipts into the
    /// targeted message rather than appending noise — exactly as a real messenger renders them.</summary>
    public void Apply(ChatMessage m)
    {
        switch (m.Kind)
        {
            case ChatKind.Edit: if (m.RefId is not null && _byId.TryGetValue(m.RefId, out var em)) em.EditedText = m.Text; break;
            case ChatKind.Delete: if (m.RefId is not null && _byId.TryGetValue(m.RefId, out var dm)) dm.Deleted = true; break;
            case ChatKind.Reaction: if (m.RefId is not null && _byId.TryGetValue(m.RefId, out var rm)) rm.Reactions[m.FromPub] = m.Text; break;
            case ChatKind.ReadReceipt: if (m.RefId is not null && _byId.TryGetValue(m.RefId, out var pm)) pm.ReadBy.Add(m.FromPub); break;
            case ChatKind.Typing: break;                  // transient; not stored in history
            default: History.Add(m); _byId[m.Id] = m; break;   // Text / Reply / Media
        }
    }
}

public static class Messenger
{
    /// <summary>Serialize a message to its on-chain payload (carried inside CHAT-2P/CHAT-GROUP).</summary>
    public static byte[] Serialize(ChatMessage m)
    {
        var w = new List<byte> { (byte)m.Kind };
        Put(w, m.Id); Put(w, m.FromPub); Put(w, m.TimeUnix.ToString()); Put(w, m.Text); Put(w, m.RefId ?? ""); Put(w, m.Media ?? "");
        return w.ToArray();
    }
    private static void Put(List<byte> o, string s) { byte[] b = Encoding.UTF8.GetBytes(s); int n = b.Length; while (n >= 0x80) { o.Add((byte)((n & 0x7f) | 0x80)); n >>= 7; } o.Add((byte)n); o.AddRange(b); }

    /// <summary>TOTAL parse of a message payload. null on malformed input.</summary>
    public static ChatMessage? Parse(byte[] data)
    {
        if (data.Length < 2) return null;
        int i = 0; var kind = (ChatKind)data[i++];
        string? Str() { int shift = 0, n = 0; while (i < data.Length) { byte b = data[i++]; n |= (b & 0x7f) << shift; if ((b & 0x80) == 0) break; shift += 7; if (shift > 21) return null; } if (n < 0 || i + n > data.Length) return null; string s = Encoding.UTF8.GetString(data, i, n); i += n; return s; }
        string? id = Str(), from = Str(), time = Str(), text = Str(), refId = Str(), media = Str();
        if (id is null || from is null || time is null || text is null || refId is null || media is null) return null;
        if (!long.TryParse(time, out long t)) return null;
        return new ChatMessage(id, kind, from, t, text, refId.Length == 0 ? null : refId, media.Length == 0 ? null : media);
    }

    private static long Now() => DateTimeOffset.UtcNow.ToUnixTimeSeconds();
    private static string NewId() => Tx.ToHex(System.Security.Cryptography.RandomNumberGenerator.GetBytes(8));

    public static ChatMessage Text(string fromPub, string text) => new(NewId(), ChatKind.Text, fromPub, Now(), text, null, null);
    public static ChatMessage Reply(string fromPub, string toMsgId, string text) => new(NewId(), ChatKind.Reply, fromPub, Now(), text, toMsgId, null);
    public static ChatMessage React(string fromPub, string toMsgId, string emoji) => new(NewId(), ChatKind.Reaction, fromPub, Now(), emoji, toMsgId, null);
    public static ChatMessage Edit(string fromPub, string msgId, string newText) => new(NewId(), ChatKind.Edit, fromPub, Now(), newText, msgId, null);
    public static ChatMessage Delete(string fromPub, string msgId) => new(NewId(), ChatKind.Delete, fromPub, Now(), "", msgId, null);
    public static ChatMessage Read(string fromPub, string msgId) => new(NewId(), ChatKind.ReadReceipt, fromPub, Now(), "", msgId, null);
    public static ChatMessage Media(string fromPub, string mediaRef, string caption) => new(NewId(), ChatKind.Media, fromPub, Now(), caption, null, mediaRef);

    // ---- on-wire framing: each chat TYPE is its OWN protocol — CHAT-2P (#2, two-person) and
    // CHAT-GROUP (#3, group/broadcast). A frame is TxProtocol.Stamp(type, convId ‖ message) so a
    // receiver routes by protocol number + conversation id, exactly as it extracts a protocol off IP. ----
    public static byte[] WireOut(TxType type, string convId, ChatMessage m)
    {
        var inner = new List<byte>();
        Put(inner, convId);
        inner.AddRange(Serialize(m));
        return TxProtocol.Stamp(type, inner.ToArray());
    }

    /// <summary>TOTAL parse of a chat frame: returns the protocol type, conversation id and message,
    /// or null if it is not a CHAT-2P/CHAT-GROUP frame or is malformed (never throws).</summary>
    public static (TxType type, string convId, ChatMessage msg)? WireIn(byte[] data)
    {
        var h = TxProtocol.Read(data);
        if (h is null || (h.Value.type is not TxType.Chat2P and not TxType.ChatGroup)) return null;
        var p = h.Value.payload; int i = 0, shift = 0, n = 0;
        while (i < p.Length) { byte b = p[i++]; n |= (b & 0x7f) << shift; if ((b & 0x80) == 0) break; shift += 7; if (shift > 21) return null; }
        if (n < 0 || i + n > p.Length) return null;
        string convId = Encoding.UTF8.GetString(p, i, n); i += n;
        var m = Parse(p[i..]);
        return m is null ? null : (h.Value.type, convId, m);
    }

    /// <summary>The stable conversation id for a two-person chat (order-independent), so both ends
    /// map the same DM to the same history regardless of who sent.</summary>
    public static string DmId(string pubA, string pubB)
        => string.CompareOrdinal(pubA, pubB) < 0 ? $"dm:{pubA}:{pubB}" : $"dm:{pubB}:{pubA}";
}
