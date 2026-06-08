// Estates.Core/BsvWire.cs — the real Bitcoin-SV P2P WIRE PROTOCOL, library-free. The in-client
// node speaks this directly to BSV network peers (and the same framing rides the IP-to-IP game
// links). NO third-party library: framing is in-tree, hashing is Tx.Hash256 (double SHA-256).
//
// Message on the wire: magic(4) ‖ command(12, NUL-padded ASCII) ‖ length(4 LE) ‖ checksum(4 =
// first 4 bytes of double-SHA256(payload)) ‖ payload(length). Every decoder here is TOTAL and
// BOUNDED — a hostile peer can never make it throw or allocate unbounded (MilSpec boundary rule).
//
// Network magic + default ports come from the BSV chainparams (pchMessageStart). The same code
// path serves mainnet / testnet / regtest — only the magic + seed peers differ (a config tag).
using System.Text;

namespace Estates.Core;

public enum BsvNet { Mainnet, Testnet, Regtest }

public static class BsvWire
{
    public const int ProtocolVersion = 70016;
    public const ulong NodeNetwork = 1;          // NODE_NETWORK service bit (bit 0)
    // Services we advertise. CRITICAL on BSV: bit 0x20 = NODE_BITCOIN_CASH, the FORK MARKER. Strict BSV
    // mainnet nodes DROP any inbound peer that does not set it (that is how the BSV network refuses BTC
    // peers after the fork). A lenient/regtest node ignores it, which is why a peer that handshakes fine
    // locally is silently dropped by every public mainnet node. We also set NODE_BLOOM (0x04) because we
    // are an SPV/bloom client. Services = NODE_NETWORK | NODE_BLOOM | NODE_BITCOIN_CASH.
    public const ulong NodeBloom = 0x04;
    public const ulong NodeBitcoinCash = 0x20;
    public const ulong Services = NodeNetwork | NodeBloom | NodeBitcoinCash;   // 0x25
    public const int MaxPayload = 32 * 1024 * 1024;  // 32 MiB hard ceiling on any single message

    /// <summary>pchMessageStart for each network (BSV chainparams), written as 4 bytes in order.</summary>
    public static byte[] Magic(BsvNet net) => net switch
    {
        BsvNet.Mainnet => new byte[] { 0xe3, 0xe1, 0xf3, 0xe8 },
        BsvNet.Testnet => new byte[] { 0xf4, 0xe5, 0xf3, 0xf4 },
        BsvNet.Regtest => new byte[] { 0xda, 0xb5, 0xbf, 0xfa },
        _ => throw new ArgumentOutOfRangeException(nameof(net)),
    };

    public static int DefaultPort(BsvNet net) => net switch
    {
        BsvNet.Mainnet => 8333, BsvNet.Testnet => 18333, BsvNet.Regtest => 18444,
        _ => throw new ArgumentOutOfRangeException(nameof(net)),
    };

    // ---- envelope ----
    /// <summary>Frame a full network message: magic ‖ command ‖ len ‖ checksum ‖ payload.</summary>
    public static byte[] Frame(BsvNet net, string command, byte[] payload)
    {
        if (payload.Length > MaxPayload) throw new ArgumentException("payload exceeds MaxPayload");
        var cmd = new byte[12];
        byte[] c = Encoding.ASCII.GetBytes(command);
        if (c.Length > 12) throw new ArgumentException("command name too long");
        Array.Copy(c, cmd, c.Length);
        byte[] checksum = Tx.Hash256(payload);  // double SHA-256
        var o = new byte[24 + payload.Length];
        Array.Copy(Magic(net), 0, o, 0, 4);
        Array.Copy(cmd, 0, o, 4, 12);
        WriteU32LE(o, 16, (uint)payload.Length);
        Array.Copy(checksum, 0, o, 20, 4);
        Array.Copy(payload, 0, o, 24, payload.Length);
        return o;
    }

    public sealed record Message(string Command, byte[] Payload);

    /// <summary>TOTAL decoder: pull one complete, checksum-valid message off the front of `buf`.
    /// Returns (message, bytesConsumed). message is null when more bytes are needed (consumed=0) or
    /// when the magic/length/checksum is invalid (the caller resynchronises). Never throws.</summary>
    public static (Message? msg, int consumed) TryRead(BsvNet net, ReadOnlySpan<byte> buf)
    {
        if (buf.Length < 24) return (null, 0);                       // need a full header first
        byte[] magic = Magic(net);
        if (!buf[..4].SequenceEqual(magic)) return (null, -1);       // bad magic → caller resyncs
        uint len = ReadU32LE(buf, 16);
        if (len > MaxPayload) return (null, -1);                     // hostile length → drop/resync
        if (buf.Length < 24 + (int)len) return (null, 0);            // payload not all here yet
        ReadOnlySpan<byte> payload = buf.Slice(24, (int)len);
        byte[] want = Tx.Hash256(payload.ToArray());
        if (!buf.Slice(20, 4).SequenceEqual(want.AsSpan(0, 4))) return (null, 24 + (int)len); // bad checksum → skip it
        int end = 0; while (end < 12 && buf[4 + end] != 0) end++;
        string command = Encoding.ASCII.GetString(buf.Slice(4, end));
        return (new Message(command, payload.ToArray()), 24 + (int)len);
    }

    // ---- payload builders ----
    /// <summary>`version` payload: our advertised version, services, time, peer/our net-addr, nonce,
    /// user-agent, start-height, relay flag.</summary>
    public static byte[] Version(long nowUnix, ulong nonce, string userAgent, int startHeight, byte[] peerIpv4, int peerPort)
    {
        var w = new List<byte>(128);
        WriteI32(w, ProtocolVersion);
        WriteU64(w, Services);                            // advertise NODE_NETWORK|NODE_BLOOM|NODE_BITCOIN_CASH
        WriteI64(w, nowUnix);
        NetAddr(w, Services, peerIpv4, peerPort);         // addr_recv (the peer)
        NetAddr(w, Services, new byte[4], 0);             // addr_from (us; unspecified)
        WriteU64(w, nonce);
        VarStr(w, userAgent);
        WriteI32(w, startHeight);
        w.Add(0x00);                                     // relay = false (we pull what we want)
        return w.ToArray();
    }

    public static byte[] Ping(ulong nonce) { var w = new List<byte>(8); WriteU64(w, nonce); return w.ToArray(); }
    public static byte[] Pong(ulong nonce) => Ping(nonce);

    /// <summary>`inv`/`getdata` vector of (type, 32-byte hash). type 1 = MSG_TX, 2 = MSG_BLOCK.</summary>
    public static byte[] InvVector(IEnumerable<(uint type, byte[] hash)> items)
    {
        var list = items.ToList();
        var w = new List<byte>();
        VarInt(w, (ulong)list.Count);
        foreach (var (type, hash) in list) { WriteU32(w, type); if (hash.Length != 32) throw new ArgumentException("inv hash must be 32 bytes"); w.AddRange(hash); }
        return w.ToArray();
    }

    /// <summary>`getheaders`: protocol version, a block-locator (newest→oldest), and a hash-stop (0 = as many as possible).</summary>
    public static byte[] GetHeaders(IReadOnlyList<byte[]> locator, byte[]? hashStop = null)
    {
        var w = new List<byte>();
        WriteI32(w, ProtocolVersion);
        VarInt(w, (ulong)locator.Count);
        foreach (var h in locator) { if (h.Length != 32) throw new ArgumentException("locator hash must be 32 bytes"); w.AddRange(h); }
        w.AddRange(hashStop ?? new byte[32]);
        return w.ToArray();
    }

    // ---- TOTAL parsers for inbound payloads (bounded; never throw) ----
    /// <summary>Parse an inv/getdata vector. Returns null on malformed/over-bounded input.</summary>
    public static List<(uint type, byte[] hash)>? ParseInv(byte[] payload)
    {
        var r = new SpanReader(payload);
        if (!r.TryVarInt(out ulong n) || n > 50_000) return null;     // protocol cap on inv entries
        var outp = new List<(uint, byte[])>((int)Math.Min(n, 4096));
        for (ulong i = 0; i < n; i++)
        {
            if (!r.TryU32(out uint type) || !r.TryBytes(32, out byte[] hash)) return null;
            outp.Add((type, hash));
        }
        return r.AtEnd ? outp : null;
    }

    /// <summary>Parse a `headers` message into raw 80-byte block headers. Returns null on malformed input.</summary>
    public static List<byte[]>? ParseHeaders(byte[] payload)
    {
        var r = new SpanReader(payload);
        if (!r.TryVarInt(out ulong n) || n > 2_000) return null;      // protocol cap (2000 headers)
        var outp = new List<byte[]>((int)Math.Min(n, 2000));
        for (ulong i = 0; i < n; i++)
        {
            if (!r.TryBytes(80, out byte[] hdr)) return null;
            if (!r.TryVarInt(out _)) return null;                     // tx_count (0 in a headers msg)
            outp.Add(hdr);
        }
        return r.AtEnd ? outp : null;
    }

    public static bool TryParsePing(byte[] payload, out ulong nonce)
    {
        nonce = 0; if (payload.Length < 8) return false;
        nonce = ReadU64LE(payload, 0); return true;
    }

    // ---- low-level LE encoders ----
    private static void WriteI32(List<byte> w, int v) => WriteU32(w, (uint)v);
    private static void WriteU32(List<byte> w, uint v) { for (int i = 0; i < 4; i++) w.Add((byte)(v >> (8 * i))); }
    private static void WriteI64(List<byte> w, long v) => WriteU64(w, (ulong)v);
    private static void WriteU64(List<byte> w, ulong v) { for (int i = 0; i < 8; i++) w.Add((byte)(v >> (8 * i))); }
    private static void WriteU32LE(byte[] o, int off, uint v) { for (int i = 0; i < 4; i++) o[off + i] = (byte)(v >> (8 * i)); }
    private static uint ReadU32LE(ReadOnlySpan<byte> b, int off) { uint v = 0; for (int i = 0; i < 4; i++) v |= (uint)b[off + i] << (8 * i); return v; }
    private static ulong ReadU64LE(ReadOnlySpan<byte> b, int off) { ulong v = 0; for (int i = 0; i < 8; i++) v |= (ulong)b[off + i] << (8 * i); return v; }

    internal static void VarInt(List<byte> w, ulong n)
    {
        if (n < 0xfd) w.Add((byte)n);
        else if (n <= 0xffff) { w.Add(0xfd); w.Add((byte)n); w.Add((byte)(n >> 8)); }
        else if (n <= 0xffffffff) { w.Add(0xfe); WriteU32(w, (uint)n); }
        else { w.Add(0xff); WriteU64(w, n); }
    }
    private static void VarStr(List<byte> w, string s) { byte[] b = Encoding.ASCII.GetBytes(s); VarInt(w, (ulong)b.Length); w.AddRange(b); }
    private static void NetAddr(List<byte> w, ulong services, byte[] ipv4, int port)
    {
        WriteU64(w, services);
        // 16-byte IPv6: IPv4-mapped prefix ::ffff:a.b.c.d
        for (int i = 0; i < 10; i++) w.Add(0x00); w.Add(0xff); w.Add(0xff);
        w.AddRange(ipv4.Length == 4 ? ipv4 : new byte[4]);
        w.Add((byte)(port >> 8)); w.Add((byte)port);   // port is BIG-endian on the wire
    }

    /// <summary>A total, bounds-checked reader over a byte payload (never throws / over-reads).</summary>
    internal struct SpanReader
    {
        private readonly byte[] _b; private int _i;
        public SpanReader(byte[] b) { _b = b; _i = 0; }
        public bool AtEnd => _i == _b.Length;
        public bool TryU32(out uint v) { v = 0; if (_i + 4 > _b.Length) return false; for (int k = 0; k < 4; k++) v |= (uint)_b[_i + k] << (8 * k); _i += 4; return true; }
        public bool TryBytes(int n, out byte[] v) { v = Array.Empty<byte>(); if (n < 0 || _i + n > _b.Length) return false; v = _b[_i..(_i + n)]; _i += n; return true; }
        public bool TryVarInt(out ulong v)
        {
            v = 0; if (_i >= _b.Length) return false;
            byte p = _b[_i++];
            if (p < 0xfd) { v = p; return true; }
            int n = p == 0xfd ? 2 : p == 0xfe ? 4 : 8;
            if (_i + n > _b.Length) return false;
            for (int k = 0; k < n; k++) v |= (ulong)_b[_i + k] << (8 * k);
            _i += n; return true;
        }
    }
}
