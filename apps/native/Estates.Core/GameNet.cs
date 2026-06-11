// Estates.Core/GameNet.cs — the actual socket transport: two physical machines play over a TCP connection.
//
// GameSession is the verified game logic and Encode/Decode is the wire format; GameNet is the pipe that
// carries those packets between two peers over a real network socket (length-prefixed frames, no server in
// the middle — one peer listens, the other dials). Each side still runs its own GameSession and re-verifies
// every received move, so the network is untrusted: a corrupted or forged frame is rejected by the engine
// the same way it would be in memory.
using System.IO;
using System.Net;
using System.Net.Sockets;

namespace Estates.Core;

public sealed class GameNet : IDisposable
{
    private readonly TcpClient _client;
    private readonly NetworkStream _stream;
    private GameNet(TcpClient c) { _client = c; _stream = c.GetStream(); }

    /// <summary>Start listening for one peer (host side). Returns the bound listener; pass it to Accept.</summary>
    public static TcpListener Listen(int port)
    {
        var l = new TcpListener(IPAddress.Loopback, port);
        l.Start();
        return l;
    }

    /// <summary>Accept the dialing peer (blocks until it connects).</summary>
    public static GameNet Accept(TcpListener l) => new(l.AcceptTcpClient());

    /// <summary>Dial the host peer.</summary>
    public static GameNet Connect(string host, int port)
    {
        var c = new TcpClient();
        c.Connect(host, port);
        return new GameNet(c);
    }

    /// <summary>Send a move packet to the peer over the socket (4-byte length prefix + the wire bytes).</summary>
    public void Send(GameSession.MovePacket p)
    {
        byte[] b = GameSession.Encode(p);
        byte[] len = { (byte)(b.Length >> 24), (byte)(b.Length >> 16), (byte)(b.Length >> 8), (byte)b.Length };
        _stream.Write(len, 0, 4);
        _stream.Write(b, 0, b.Length);
        _stream.Flush();
    }

    /// <summary>Receive the next move packet from the peer (blocks until a full frame arrives).</summary>
    public GameSession.MovePacket Receive()
    {
        byte[] lb = ReadExact(4);
        int len = (lb[0] << 24) | (lb[1] << 16) | (lb[2] << 8) | lb[3];
        if (len < 0 || len > 1 << 20) throw new IOException("bad frame length");
        return GameSession.Decode(ReadExact(len));
    }

    private byte[] ReadExact(int n)
    {
        var b = new byte[n]; int got = 0;
        while (got < n)
        {
            int r = _stream.Read(b, got, n - got);
            if (r <= 0) throw new IOException("peer closed");
            got += r;
        }
        return b;
    }

    public void Dispose() { try { _stream.Dispose(); } catch { } try { _client.Dispose(); } catch { } }
}
