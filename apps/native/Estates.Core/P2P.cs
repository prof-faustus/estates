// Estates.Core/P2P.cs — TRUE peer-to-peer transport. NO server. Ever.
//
// There is no relay, no rendezvous, no signalling, no central process of any kind.
// Each running app IS a node:
//   * DISCOVERY — it announces its presence on the local network with UDP multicast
//     (no server, no URL to share). Every node hears every other node's announcement
//     and keeps a list of live peers that AGES OUT — when a peer closes, its
//     announcements stop and it vanishes from the lobby within seconds. The lobby is
//     therefore always clean: it only ever shows peers that are alive right now.
//   * LINK — to join another player's table a node connects DIRECTLY to that peer
//     over TCP (the address comes from the peer's own multicast announcement, never a
//     server). Game frames flow peer-to-peer over that socket.
//
// A "host" is just a player's app — never a server. Close it and its table is gone.
//
// GUARANTEED TERMINATION: Dispose() tears down every socket and background loop, and
// the loops are cancellation-driven + the threads are background threads, so when the
// process exits NOTHING is ever left running. Nothing of yours can outlive your app.
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Collections.Concurrent;

namespace Estates.Core;

/// <summary>A peer seen alive on the network right now (from its multicast announce).</summary>
public sealed record PeerInfo(string NodeId, string Name, string Host, int Port, string? TableId, string? TableInfo, DateTime LastSeen);

/// <summary>One direct TCP link to another peer (length-prefixed frames).</summary>
public sealed class PeerLink : IDisposable
{
    private readonly TcpClient _tcp;
    private readonly NetworkStream _stream;
    private readonly CancellationTokenSource _cts = new();
    public string RemoteId { get; internal set; } = "";
    public event Action<PeerLink, byte[]>? OnFrame;
    public event Action<PeerLink>? OnClosed;

    internal PeerLink(TcpClient tcp)
    {
        _tcp = tcp;
        _stream = tcp.GetStream();
        var t = new Thread(ReadLoop) { IsBackground = true, Name = "p2p-link" };
        t.Start();
    }

    private void ReadLoop()
    {
        var lenBuf = new byte[4];
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                if (!ReadExact(lenBuf, 4)) break;
                int len = (lenBuf[0] << 24) | (lenBuf[1] << 16) | (lenBuf[2] << 8) | lenBuf[3];
                if (len < 0 || len > P2PNode.MaxFrame) break;       // hostile/garbage length → drop the link
                var payload = new byte[len];
                if (!ReadExact(payload, len)) break;
                OnFrame?.Invoke(this, payload);
            }
        }
        catch { /* link dropped */ }
        finally { OnClosed?.Invoke(this); Dispose(); }
    }

    private bool ReadExact(byte[] buf, int n)
    {
        int off = 0;
        while (off < n)
        {
            int r;
            try { r = _stream.Read(buf, off, n - off); } catch { return false; }
            if (r <= 0) return false;
            off += r;
        }
        return true;
    }

    /// <summary>Send one frame (length-prefixed). Non-throwing: a dead link is just dropped.</summary>
    public void Send(byte[] frame)
    {
        if (frame.Length > P2PNode.MaxFrame) return;
        var hdr = new byte[4] { (byte)(frame.Length >> 24), (byte)(frame.Length >> 16), (byte)(frame.Length >> 8), (byte)frame.Length };
        try { lock (_stream) { _stream.Write(hdr, 0, 4); _stream.Write(frame, 0, frame.Length); _stream.Flush(); } }
        catch { Dispose(); }
    }

    public void Send(string hexFrame) => Send(Encoding.UTF8.GetBytes(hexFrame));

    public void Dispose()
    {
        if (_cts.IsCancellationRequested) return;
        _cts.Cancel();
        try { _stream.Dispose(); } catch { }
        try { _tcp.Close(); } catch { }
    }
}

/// <summary>
/// A true P2P node: serverless LAN discovery (UDP multicast) + direct peer links (TCP).
/// No central process is contacted or created. Dispose() (or process exit) leaves nothing.
/// </summary>
public sealed class P2PNode : IDisposable
{
    public const int MaxFrame = 1 << 20;                 // 1 MiB per frame — generous, bounded
    private static readonly IPAddress Group = IPAddress.Parse("239.255.41.42"); // ESTATES discovery group
    private const int DiscoveryPort = 41420;
    private static readonly TimeSpan AnnounceEvery = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan PeerTtl = TimeSpan.FromSeconds(7);          // a peer not heard from in 7s is gone

    public string NodeId { get; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; }
    /// <summary>The table this node is hosting/advertising, or null. Set by the lobby.</summary>
    public (string id, string info)? Advertised { get; set; }

    private readonly TcpListener _listener;
    private readonly int _tcpPort;
    private readonly UdpClient _udp;
    private readonly CancellationTokenSource _cts = new();
    private readonly ConcurrentDictionary<string, PeerInfo> _peers = new();
    private readonly ConcurrentBag<PeerLink> _links = new();
    private bool _disposed;

    public event Action<PeerInfo>? OnPeerDiscovered;
    public event Action<string>? OnPeerLost;
    public event Action<PeerLink>? OnLink;             // a peer connected to us OR we connected to a peer

    public P2PNode(string name)
    {
        Name = name;
        // bind a TCP listener on an ephemeral loopback-or-LAN port for direct peer links
        _listener = new TcpListener(IPAddress.Any, 0);
        _listener.Start();
        _tcpPort = ((IPEndPoint)_listener.LocalEndpoint).Port;

        // join the multicast discovery group (NO server — a LAN multicast group)
        _udp = new UdpClient();
        _udp.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
        _udp.Client.Bind(new IPEndPoint(IPAddress.Any, DiscoveryPort));
        _udp.JoinMulticastGroup(Group);

        Start(AcceptLoop, "p2p-accept");
        Start(DiscoveryRecvLoop, "p2p-discovery-recv");
        Start(AnnounceLoop, "p2p-announce");
        Start(PruneLoop, "p2p-prune");
    }

    private void Start(Action loop, string name)
    {
        var t = new Thread(() => { try { loop(); } catch { } }) { IsBackground = true, Name = name };
        t.Start();
    }

    // ---- discovery (serverless multicast) ----

    private void AnnounceLoop()
    {
        var ep = new IPEndPoint(Group, DiscoveryPort);
        while (!_cts.IsCancellationRequested)
        {
            try
            {
                var msg = JsonSerializer.Serialize(new AnnounceMsg(NodeId, Name, _tcpPort, Advertised?.id, Advertised?.info));
                var b = Encoding.UTF8.GetBytes("ESTATES-P2P\n" + msg);
                _udp.Send(b, b.Length, ep);
            }
            catch { }
            _cts.Token.WaitHandle.WaitOne(AnnounceEvery);
        }
    }

    private void DiscoveryRecvLoop()
    {
        var from = new IPEndPoint(IPAddress.Any, 0);
        while (!_cts.IsCancellationRequested)
        {
            byte[] data;
            try { data = _udp.Receive(ref from); } catch { if (_cts.IsCancellationRequested) break; continue; }
            try
            {
                var s = Encoding.UTF8.GetString(data);
                if (!s.StartsWith("ESTATES-P2P\n")) continue;
                var a = JsonSerializer.Deserialize<AnnounceMsg>(s["ESTATES-P2P\n".Length..]);
                if (a is null || a.NodeId == NodeId) continue;     // ignore our own announce
                var host = from.Address.ToString();
                var info = new PeerInfo(a.NodeId, a.Name ?? "player", host, a.TcpPort, a.TableId, a.TableInfo, DateTime.UtcNow);
                bool isNew = !_peers.ContainsKey(a.NodeId);
                _peers[a.NodeId] = info;
                if (isNew) OnPeerDiscovered?.Invoke(info);
            }
            catch { }
        }
    }

    private void PruneLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            _cts.Token.WaitHandle.WaitOne(TimeSpan.FromSeconds(2));
            var now = DateTime.UtcNow;
            foreach (var kv in _peers)
            {
                if (now - kv.Value.LastSeen > PeerTtl && _peers.TryRemove(kv.Key, out _))
                    OnPeerLost?.Invoke(kv.Key);
            }
        }
    }

    /// <summary>Peers alive on the network right now (closed peers have already aged out).</summary>
    public IReadOnlyList<PeerInfo> Peers() => _peers.Values.OrderBy(p => p.Name).ToList();

    // ---- direct peer links (TCP) ----

    private void AcceptLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            TcpClient c;
            try { c = _listener.AcceptTcpClient(); } catch { if (_cts.IsCancellationRequested) break; continue; }
            var link = new PeerLink(c);
            _links.Add(link);
            OnLink?.Invoke(link);
        }
    }

    /// <summary>Connect DIRECTLY to a discovered peer (no server in between). Returns the link or null.</summary>
    public PeerLink? Connect(PeerInfo peer)
    {
        try
        {
            var c = new TcpClient();
            c.Connect(peer.Host, peer.Port);
            var link = new PeerLink(c) { RemoteId = peer.NodeId };
            _links.Add(link);
            OnLink?.Invoke(link);
            return link;
        }
        catch { return null; }
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        foreach (var l in _links) { try { l.Dispose(); } catch { } }
        try { _udp.DropMulticastGroup(Group); } catch { }
        try { _udp.Close(); } catch { }
        try { _listener.Stop(); } catch { }
    }

    private sealed record AnnounceMsg(string NodeId, string? Name, int TcpPort, string? TableId, string? TableInfo);
}
