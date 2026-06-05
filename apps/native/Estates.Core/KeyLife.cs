// Estates.Core/KeyLife.cs — native port of @estates/keylife verification.
//
// The one-game-key rule, verified on the native side identically to the audited
// TS reference: a signed genesis key manifest binds every key to ONE gameId, and
// cross-game key reuse is rejected. The canonical signed body is byte-for-byte the
// same JSON the TS signs (fixed field order: k, gameId, protocolVersion, paramsHash,
// entries:[purpose,pub,keyType,seat]), so an Ed25519 signature made in TS verifies
// here and vice-versa. Ed25519 via BouncyCastle (reference Rfc8032).
using System.Globalization;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Math.EC.Rfc8032;

namespace Estates.Core;

public sealed record KeyEntry(string Purpose, string Pub, string KeyType, int? Seat);

public sealed class KeyManifest
{
    public required string GameId { get; init; }
    public required string ProtocolVersion { get; init; }
    public required string ParamsHash { get; init; }
    public required List<KeyEntry> Entries { get; init; }
    public required string AuthorityPub { get; init; }
    public required string Sig { get; init; }
}

public static class KeyLife
{
    private static readonly HashSet<string> Purposes = new() { "genesis", "seat", "card", "holder", "chat", "bank", "settlement", "trade" };
    private static readonly HashSet<string> KeyTypes = new() { "ed25519", "secp256k1" };
    private const int MaxEntries = 4096, Hex32 = 64, EdPub = 64, EdSig = 128, SecpPub = 66, MaxSeat = 7;

    private static bool IsHexLen(string? x, int n) => x != null && x.Length == n && x.All(Uri.IsHexDigit);

    private static byte[] FromHex(string h)
    {
        var b = new byte[h.Length / 2];
        for (int i = 0; i < b.Length; i++) b[i] = byte.Parse(h.AsSpan(i * 2, 2), NumberStyles.HexNumber, CultureInfo.InvariantCulture);
        return b;
    }

    // The EXACT bytes the authority signs (mirrors TS manifestBody): a key-ordered
    // JSON with NO spaces. seat is the int or null.
    private static byte[] ManifestBody(KeyManifest m)
    {
        var sb = new StringBuilder();
        sb.Append("{\"k\":\"estates-keymanifest-v1\",\"gameId\":");
        Str(sb, m.GameId); sb.Append(",\"protocolVersion\":"); Str(sb, m.ProtocolVersion);
        sb.Append(",\"paramsHash\":"); Str(sb, m.ParamsHash); sb.Append(",\"entries\":[");
        for (int i = 0; i < m.Entries.Count; i++)
        {
            if (i > 0) sb.Append(',');
            var e = m.Entries[i];
            sb.Append("{\"purpose\":"); Str(sb, e.Purpose);
            sb.Append(",\"pub\":"); Str(sb, e.Pub);
            sb.Append(",\"keyType\":"); Str(sb, e.KeyType);
            sb.Append(",\"seat\":").Append(e.Seat?.ToString(CultureInfo.InvariantCulture) ?? "null");
            sb.Append('}');
        }
        sb.Append("]}");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // JSON string (our values are simple ASCII — matches JSON.stringify).
    private static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            if (c == '"') sb.Append("\\\"");
            else if (c == '\\') sb.Append("\\\\");
            else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            else sb.Append(c);
        }
        sb.Append('"');
    }

    /// <summary>Verify one manifest: structure + bounds + no in-game reuse + the
    /// authority Ed25519 signature. Total: returns (false, reason) on anything
    /// unexpected; never throws.</summary>
    public static (bool Ok, string Reason) VerifyManifest(KeyManifest? m)
    {
        try
        {
            if (m is null) return (false, "null");
            if (!IsHexLen(m.GameId, Hex32)) return (false, "gameId");
            if (string.IsNullOrEmpty(m.ProtocolVersion) || m.ProtocolVersion.Length > 64) return (false, "protocolVersion");
            if (!IsHexLen(m.ParamsHash, Hex32)) return (false, "paramsHash");
            if (!IsHexLen(m.AuthorityPub, EdPub)) return (false, "authorityPub");
            if (!IsHexLen(m.Sig, EdSig)) return (false, "sig");
            if (m.Entries.Count == 0 || m.Entries.Count > MaxEntries) return (false, "entries count");

            var seenPub = new HashSet<string>(); var seenSeat = new HashSet<int>(); int genesis = 0;
            foreach (var e in m.Entries)
            {
                if (!Purposes.Contains(e.Purpose)) return (false, "purpose");
                if (!KeyTypes.Contains(e.KeyType)) return (false, "keyType");
                int want = e.KeyType == "ed25519" ? EdPub : SecpPub;
                if (!IsHexLen(e.Pub, want)) return (false, "pub length");
                if (!seenPub.Add(e.Pub)) return (false, "in-game key reuse");
                if (e.Purpose == "seat")
                {
                    if (e.Seat is null || e.Seat < 0 || e.Seat > MaxSeat) return (false, "seat range");
                    if (!seenSeat.Add(e.Seat.Value)) return (false, "duplicate seat");
                }
                if (e.Purpose == "genesis")
                {
                    genesis++;
                    if (e.KeyType != "ed25519") return (false, "genesis keyType");
                    if (e.Pub != m.AuthorityPub) return (false, "genesis != authorityPub");
                }
            }
            if (genesis != 1) return (false, "exactly one genesis");

            byte[] body = ManifestBody(m), sig = FromHex(m.Sig), pub = FromHex(m.AuthorityPub);
            if (sig.Length != 64 || pub.Length != 32) return (false, "sig/pub bytes");
            if (!Ed25519.Verify(sig, 0, pub, 0, body, 0, body.Length)) return (false, "authority signature invalid");
            return (true, "verified");
        }
        catch (Exception ex) { return (false, "threw: " + ex.Message); }
    }

    /// <summary>Reject the SAME pubkey appearing under two different gameIds.</summary>
    public static (bool Ok, string Reason) VerifyNoCrossGameReuse(IReadOnlyList<KeyManifest> manifests)
    {
        var owner = new Dictionary<string, string>();
        foreach (var m in manifests)
            foreach (var e in m.Entries)
            {
                if (owner.TryGetValue(e.Pub, out var prev) && prev != m.GameId) return (false, "cross-game key reuse");
                owner[e.Pub] = m.GameId;
            }
        return (true, "no cross-game reuse");
    }

    public static KeyManifest Parse(JsonElement el)
    {
        var entries = new List<KeyEntry>();
        foreach (var e in el.GetProperty("entries").EnumerateArray())
            entries.Add(new KeyEntry(
                e.GetProperty("purpose").GetString()!,
                e.GetProperty("pub").GetString()!,
                e.GetProperty("keyType").GetString()!,
                e.TryGetProperty("seat", out var s) && s.ValueKind == JsonValueKind.Number ? s.GetInt32() : null));
        return new KeyManifest
        {
            GameId = el.GetProperty("gameId").GetString()!,
            ProtocolVersion = el.GetProperty("protocolVersion").GetString()!,
            ParamsHash = el.GetProperty("paramsHash").GetString()!,
            Entries = entries,
            AuthorityPub = el.GetProperty("authorityPub").GetString()!,
            Sig = el.GetProperty("sig").GetString()!,
        };
    }
}
