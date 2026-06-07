// Estates.Core/EstateGossip.cs — the ESTATE gossip + query overlay: how estate nodes find each other,
// chat partners, and games. This is NOT Bitcoin gossip; it rides the estate P2P link. Messages are
// typed, length-prefixed and parsed totally. ANNOUNCE advertises a node, its identity pubkey and what
// it offers (e.g. a table/game tag); QUERY asks for nodes/games matching a tag; REPLY returns a match.
// GossipState tracks live peers (ages them out) so the lobby only ever shows who is live right now.
using System.Text;

namespace Estates.Core;

public enum GossipKind : byte { Announce = 1, Query = 2, Reply = 3 }

public sealed record GossipPeer(string NodeId, string IdentityPub, string Offer, long SeenUnix);

public static class EstateGossip
{
    private static void Put(List<byte> o, string s) { var b = Encoding.UTF8.GetBytes(s); int n = b.Length; while (n >= 0x80) { o.Add((byte)((n & 0x7f) | 0x80)); n >>= 7; } o.Add((byte)n); o.AddRange(b); }

    public static byte[] Encode(GossipKind kind, string nodeId, string identityPub, string offer)
    {
        var o = new List<byte> { (byte)kind };
        Put(o, nodeId); Put(o, identityPub); Put(o, offer);
        return o.ToArray();
    }

    /// <summary>TOTAL parse — null on malformed input (never throws).</summary>
    public static (GossipKind kind, string nodeId, string identityPub, string offer)? Decode(byte[] data)
    {
        if (data is null || data.Length < 2) return null;
        int i = 0; var kind = (GossipKind)data[i++];
        string? Str() { int shift = 0, n = 0; while (i < data.Length) { byte b = data[i++]; n |= (b & 0x7f) << shift; if ((b & 0x80) == 0) break; shift += 7; if (shift > 21) return null; } if (n < 0 || i + n > data.Length) return null; var s = Encoding.UTF8.GetString(data, i, n); i += n; return s; }
        string? id = Str(), pub = Str(), offer = Str();
        if (id is null || pub is null || offer is null) return null;
        return (kind, id, pub, offer);
    }
}

public sealed class GossipState
{
    private readonly object _lock = new();
    private readonly Dictionary<string, GossipPeer> _peers = new();
    public int TtlSeconds { get; set; } = 30;

    private static long Now() => System.DateTimeOffset.UtcNow.ToUnixTimeSeconds();

    /// <summary>Record/refresh a peer from an ANNOUNCE.</summary>
    public void OnAnnounce(string nodeId, string identityPub, string offer)
    {
        lock (_lock) _peers[nodeId] = new GossipPeer(nodeId, identityPub, offer, Now());
    }

    /// <summary>The peers seen within TTL (live right now); stale ones are pruned.</summary>
    public IReadOnlyList<GossipPeer> Live()
    {
        lock (_lock)
        {
            long cut = Now() - TtlSeconds;
            foreach (var k in new List<string>(_peers.Keys)) if (_peers[k].SeenUnix < cut) _peers.Remove(k);
            return new List<GossipPeer>(_peers.Values);
        }
    }

    /// <summary>Live peers whose offer matches a query tag (substring) — answers a QUERY.</summary>
    public IReadOnlyList<GossipPeer> Query(string tag)
    {
        var live = Live();
        if (string.IsNullOrEmpty(tag)) return live;
        var o = new List<GossipPeer>();
        foreach (var p in live) if (p.Offer.Contains(tag, System.StringComparison.OrdinalIgnoreCase)) o.Add(p);
        return o;
    }
}
