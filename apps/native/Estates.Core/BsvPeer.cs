// Estates.Core/BsvPeer.cs — a real BSV NETWORK PEER connection. The in-client node opens TCP links
// to BSV peers, runs the version/verack handshake, answers ping with pong, BROADCASTS our
// transactions (inv → getdata → tx), and pulls block headers (getheaders → headers) for SPV. This
// is the node side that puts every action ON-CHAIN by gossiping it to the network itself — no
// external/localhost RPC node. Same code path for mainnet / testnet / regtest (only magic+seed differ).
//
// Library-free: System.Net.Sockets is the .NET runtime (Microsoft), not a third party. The frame
// parser (BsvWire.TryRead) is total + bounded, so a hostile peer can never crash the read loop.
using System.Net.Sockets;
using System.Security.Cryptography;

namespace Estates.Core;

public sealed class BsvPeer : IDisposable
{
    private readonly BsvNet _net;
    private readonly TcpClient _tcp = new();
    private NetworkStream? _stream;
    private CancellationTokenSource? _cts;
    private readonly byte[] _outbox = new byte[0];   // placeholder to keep field layout obvious
    private readonly Dictionary<string, byte[]> _txPool = new();   // txid(hex) -> raw, for getdata replies
    private readonly object _gate = new();

    public string Host { get; }
    public int Port { get; }
    public bool HandshakeComplete { get; private set; }
    public string? PeerUserAgent { get; private set; }
    public int PeerStartHeight { get; private set; }

    /// <summary>Raised with each batch of validated-on-arrival raw 80-byte headers from the peer.</summary>
    public event Action<IReadOnlyList<byte[]>>? OnHeaders;
    /// <summary>Raised when the peer announces inventory (txids/blocks) to us.</summary>
    public event Action<IReadOnlyList<(uint type, byte[] hash)>>? OnInv;
    /// <summary>Raised with each raw block the peer sends in response to our getdata. Feed to ChainSync.</summary>
    public event Action<byte[]>? OnBlock;
    /// <summary>Raised after we hand a broadcast tx to the peer (it sent getdata and we sent the tx) —
    /// the confirmation that the broadcast reached the network. Carries the txid.</summary>
    public event Action<string>? OnTxSent;
    public event Action<string>? OnLog;
    /// <summary>Raised with the command name of EVERY message received from the peer (diagnostics).</summary>
    public event Action<string>? OnRecv;

    public BsvPeer(BsvNet net, string host, int port) { _net = net; Host = host; Port = port; }

    /// <summary>Connect, handshake (version/verack), and start the read loop. Throws only on a hard
    /// socket/connect failure; protocol errors after connect drop the peer, they don't crash.</summary>
    public async Task ConnectAsync(int startHeight = 0, int timeoutMs = 10_000)
    {
        using var connectCts = new CancellationTokenSource(timeoutMs);
        await _tcp.ConnectAsync(Host, Port, connectCts.Token).ConfigureAwait(false);
        _stream = _tcp.GetStream();
        _cts = new CancellationTokenSource();

        ulong nonce = BitConverter.ToUInt64(RandomNumberGenerator.GetBytes(8));
        byte[] peerIp = ResolveIpv4(Host);
        await SendAsync("version", BsvWire.Version(DateTimeOffset.UtcNow.ToUnixTimeSeconds(), nonce, "/estates:1.0/", startHeight, peerIp, Port)).ConfigureAwait(false);
        _ = Task.Run(() => ReadLoopAsync(_cts.Token));
    }

    /// <summary>Queue a raw transaction for broadcast and announce it to the peer (inv MSG_TX). When
    /// the peer asks (getdata) we send the full tx — the standard relay handshake.</summary>
    public async Task BroadcastAsync(byte[] rawTx)
    {
        string txid = Tx.ToHex(ReverseTxid(Tx.Hash256(rawTx)));   // display txid (big-endian)
        lock (_gate) _txPool[txid] = rawTx;
        byte[] invHash = Tx.Hash256(rawTx);                       // internal order for the wire
        await SendAsync("inv", BsvWire.InvVector(new[] { ((uint)1, invHash) })).ConfigureAwait(false);
        OnLog?.Invoke($"announced tx {txid[..16]}… to {Host}");
    }

    /// <summary>Ask the peer for headers following our locator (newest→oldest known hashes).</summary>
    public Task RequestHeadersAsync(IReadOnlyList<byte[]> locator)
        => SendAsync("getheaders", BsvWire.GetHeaders(locator));

    public async Task SendAsync(string command, byte[] payload)
    {
        var s = _stream ?? throw new InvalidOperationException("not connected");
        byte[] framed = BsvWire.Frame(_net, command, payload);
        await s.WriteAsync(framed).ConfigureAwait(false);
    }

    /// <summary>Ask the peer for full blocks by hash (display order); they arrive on OnBlock. Builds a
    /// getdata inv vector with MSG_BLOCK (type 2) entries, hashes converted to internal byte order.</summary>
    public async Task RequestBlocks(IReadOnlyList<string> blockHashesDisplay)
    {
        if (blockHashesDisplay is null || blockHashesDisplay.Count == 0) return;
        var p = new List<byte>();
        long c = blockHashesDisplay.Count;
        if (c < 0xfd) p.Add((byte)c);
        else { p.Add(0xfd); p.Add((byte)(c & 0xff)); p.Add((byte)((c >> 8) & 0xff)); }
        foreach (var hx in blockHashesDisplay)
        {
            byte[] h; try { h = Tx.FromHex(hx); } catch { return; }
            if (h.Length != 32) return;
            Array.Reverse(h);                                   // display -> internal
            p.Add(2); p.Add(0); p.Add(0); p.Add(0);            // MSG_BLOCK = 2 (uint32 LE)
            p.AddRange(h);
        }
        await SendAsync("getdata", p.ToArray()).ConfigureAwait(false);
    }

    private async Task ReadLoopAsync(CancellationToken ct)
    {
        var s = _stream!;
        var buf = new byte[0];
        var chunk = new byte[64 * 1024];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int n = await s.ReadAsync(chunk, ct).ConfigureAwait(false);
                if (n <= 0) { OnLog?.Invoke($"{Host} closed the connection (EOF)"); break; }   // peer closed
                buf = Concat(buf, chunk, n);
                // drain every complete message currently buffered
                for (;;)
                {
                    var (msg, consumed) = BsvWire.TryRead(_net, buf);
                    if (consumed == 0) break;                        // need more bytes
                    if (consumed < 0) { buf = Resync(buf); continue; } // bad magic/len/checksum → resync
                    buf = buf[consumed..];
                    if (msg is not null) await HandleAsync(msg).ConfigureAwait(false);
                }
                if (buf.Length > BsvWire.MaxPayload + 24) { OnLog?.Invoke("peer flooded buffer; dropping"); break; }
            }
        }
        catch (Exception ex) when (ex is IOException or OperationCanceledException or ObjectDisposedException) { /* peer gone */ }
        catch (Exception ex) { OnLog?.Invoke("read loop error: " + ex.Message); }
    }

    private async Task HandleAsync(BsvWire.Message m)
    {
        OnRecv?.Invoke(m.Command);
        switch (m.Command)
        {
            case "version":
                // record what the peer advertised, then ack
                ReadVersion(m.Payload);
                await SendAsync("verack", Array.Empty<byte>()).ConfigureAwait(false);
                break;
            case "verack":
                HandshakeComplete = true;
                OnLog?.Invoke($"handshake complete with {Host} ({PeerUserAgent})");
                break;
            case "ping":
                if (BsvWire.TryParsePing(m.Payload, out ulong nonce)) await SendAsync("pong", BsvWire.Pong(nonce)).ConfigureAwait(false);
                break;
            case "getheaders":
                await SendAsync("headers", new byte[] { 0x00 }).ConfigureAwait(false);  // we serve none (SPV leaf)
                break;
            case "getdata":
                await ServeGetData(m.Payload).ConfigureAwait(false);
                break;
            case "inv":
            {
                var inv = BsvWire.ParseInv(m.Payload);
                if (inv is not null) OnInv?.Invoke(inv);
                break;
            }
            case "headers":
            {
                var hs = BsvWire.ParseHeaders(m.Payload);
                if (hs is not null) OnHeaders?.Invoke(hs);
                break;
            }
            case "block":
                OnBlock?.Invoke(m.Payload);             // raw block → caller validates via ChainSync
                break;
            // sendheaders/feefilter/addr/etc.: safely ignored (total parser already validated framing)
        }
    }

    private async Task ServeGetData(byte[] payload)
    {
        var inv = BsvWire.ParseInv(payload);
        if (inv is null) return;
        foreach (var (type, hash) in inv)
        {
            if (type != 1) continue;                                  // MSG_TX only
            string txid = Tx.ToHex(ReverseTxid(hash));
            byte[]? raw; lock (_gate) _txPool.TryGetValue(txid, out raw);
            if (raw is not null) { await SendAsync("tx", raw).ConfigureAwait(false); OnLog?.Invoke($"sent tx {txid[..16]}… to {Host}"); OnTxSent?.Invoke(txid); }
        }
    }

    private void ReadVersion(byte[] p)
    {
        try
        {
            // version(4) services(8) time(8) addr_recv(26) addr_from(26) nonce(8) [varstr UA] height(4)
            int i = 4 + 8 + 8 + 26 + 26 + 8;
            if (i >= p.Length) return;
            ulong uaLen = p[i++];
            if (uaLen >= 0xfd) return;                                // (short UA only; longer => skip parse)
            if (i + (int)uaLen + 4 > p.Length) return;
            PeerUserAgent = System.Text.Encoding.ASCII.GetString(p, i, (int)uaLen); i += (int)uaLen;
            PeerStartHeight = (int)(p[i] | (p[i + 1] << 8) | (p[i + 2] << 16) | (p[i + 3] << 24));
        }
        catch { /* total: a malformed version just leaves UA/height unset */ }
    }

    private static byte[] ResolveIpv4(string host)
    {
        try
        {
            var addrs = System.Net.Dns.GetHostAddresses(host);
            foreach (var a in addrs) if (a.AddressFamily == AddressFamily.InterNetwork) return a.GetAddressBytes();
        }
        catch { }
        return new byte[4];
    }

    private static byte[] ReverseTxid(byte[] h) { var r = (byte[])h.Clone(); Array.Reverse(r); return r; }
    private static byte[] Concat(byte[] a, byte[] chunk, int n) { var o = new byte[a.Length + n]; Array.Copy(a, o, a.Length); Array.Copy(chunk, 0, o, a.Length, n); return o; }
    private static byte[] Resync(byte[] buf)
    {
        // drop one byte and look for the next plausible magic start; bounded, never throws.
        return buf.Length <= 1 ? Array.Empty<byte>() : buf[1..];
    }

    public void Dispose()
    {
        try { _cts?.Cancel(); } catch { }
        try { _stream?.Dispose(); } catch { }
        try { _tcp.Dispose(); } catch { }
    }
}
