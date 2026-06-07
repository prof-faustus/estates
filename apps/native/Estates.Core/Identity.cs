// Estates.Core/Identity.cs — a player's IDENTITY as an on-chain NFT CARD (protocol type #16), not a
// name string. The card carries EXPANDABLE attributes (ordered key/value pairs: name, avatar, bio,
// pubkey, …; new keys can be added any time) and is owned by the player's key. It LINKS the player's
// games + history: each new identity card spends the previous one (a re-seal chain), so a verifiable
// provenance line ties every game/chat the identity took part in back to one root card. Chat shows
// players by their identity card. Encryption (when the card is private) is ECDH-with-an-AES-key, not
// an ephemeral-key scheme. The attribute list is length-prefixed and parsed totally (never throws).
using System.Text;

namespace Estates.Core;

public sealed record IdentityCard(IReadOnlyList<(string Key, string Value)> Attributes)
{
    public string? Get(string key)
    {
        foreach (var (k, v) in Attributes) if (k == key) return v;
        return null;
    }
    public string Name => Get("name") ?? "(unnamed)";
}

public static class Identity
{
    private static void Var(List<byte> o, int n) { for (; n >= 0x80; n >>= 7) o.Add((byte)(n | 0x80)); o.Add((byte)n); }
    private static void Put(List<byte> o, string s) { byte[] b = Encoding.UTF8.GetBytes(s); Var(o, b.Length); o.AddRange(b); }

    /// <summary>Serialize the (expandable) attribute list: count, then per attr varint-len key + value.</summary>
    public static byte[] Serialize(IReadOnlyList<(string Key, string Value)> attrs)
    {
        var o = new List<byte>();
        Var(o, attrs.Count);
        foreach (var (k, v) in attrs) { Put(o, k); Put(o, v); }
        return o.ToArray();
    }

    /// <summary>TOTAL parse of an attribute list. null on any malformed/over-bounded input (never throws).</summary>
    public static IReadOnlyList<(string Key, string Value)>? Parse(byte[] data)
    {
        int i = 0;
        bool TryVar(out int val) { val = 0; int shift = 0; while (i < data.Length) { byte b = data[i++]; val |= (b & 0x7f) << shift; if ((b & 0x80) == 0) return shift < 28; shift += 7; } return false; }
        string? Str() { if (!TryVar(out int n) || n < 0 || n > 1 << 20 || i + n > data.Length) return null; string s = Encoding.UTF8.GetString(data, i, n); i += n; return s; }
        if (!TryVar(out int count) || count < 0 || count > 4096) return null;
        var outp = new List<(string, string)>(Math.Min(count, 256));
        for (int j = 0; j < count; j++) { string? k = Str(); string? v = Str(); if (k is null || v is null) return null; outp.Add((k, v)); }
        return i == data.Length ? outp : null;
    }

    /// <summary>Mint a player's identity card on-chain: a 1-sat NFT owned by the player's key, carrying
    /// the (expandable) attributes, typed IDENTITY (#16). Funded by the wallet.</summary>
    public static StandaloneWallet.BuiltTx Mint(StandaloneWallet w, IReadOnlyList<(string Key, string Value)> attrs, long feeSats)
    {
        byte[] data = TxProtocol.Stamp(TxType.Identity, Serialize(attrs));
        byte[] pkh = Recovery.Hash160(w.ChildPub(0));
        return w.BuildAndSign(new[] { new TxOutputN(1, OnChainActions.CarrierScript(data, pkh)) }, feeSats, 0);
    }

    /// <summary>Update the identity by SPENDING the prior card and minting the new attributes — the
    /// chain that links the identity's whole history (provenance back to the root card).</summary>
    public static StandaloneWallet.BuiltTx Update(StandaloneWallet w, Coin priorCard, IReadOnlyList<(string Key, string Value)> attrs, long feeSats)
    {
        byte[] data = TxProtocol.Stamp(TxType.Identity, Serialize(attrs));
        byte[] pkh = Recovery.Hash160(w.ChildPub(priorCard.AddrIndex));
        return w.BuildWithForcedInput(priorCard, new[] { new TxOutputN(1, OnChainActions.CarrierScript(data, pkh)) }, feeSats, 0);
    }

    /// <summary>Read an identity card from a typed marker's carrier data. null if it is not IDENTITY.</summary>
    public static IdentityCard? Read(byte[] carrierData)
    {
        var h = TxProtocol.Read(carrierData);
        if (h is null || h.Value.type != TxType.Identity) return null;
        var attrs = Parse(h.Value.payload);
        return attrs is null ? null : new IdentityCard(attrs);
    }
}
