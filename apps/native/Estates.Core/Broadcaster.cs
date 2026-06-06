// Estates.Core/Broadcaster.cs — LIVE transaction broadcast over the BSV P2P network. The in-client
// node connects to a real BSV peer, runs the version/verack handshake, announces the tx (inv), serves
// the peer's getdata with the full tx, and confirms once the peer has PULLED it (OnTxSent) — i.e. the
// network now has the transaction. There is NO external/localhost RPC node: the client IS the node.
//
// Same code path for regtest / testnet / mainnet — only the network magic and the peer host/port
// differ (a config tag). Funding is separate: a real UTXO enters the wallet (Fund/import or a peer
// transfer); this is the path that pushes the signed spend onto the chain.
namespace Estates.Core;

public static class Broadcaster
{
    /// <summary>Broadcast `rawTx` to one BSV peer. Returns true once the peer has requested and
    /// received the tx (the broadcast reached the network), false on connect/handshake/timeout.</summary>
    public static async Task<bool> BroadcastAsync(BsvNet net, string host, int port, byte[] rawTx, int timeoutMs = 15000)
    {
        using var peer = new BsvPeer(net, host, port);
        var pulled = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        peer.OnTxSent += _ => pulled.TrySetResult(true);

        await peer.ConnectAsync(0, timeoutMs).ConfigureAwait(false);
        var sw = System.Diagnostics.Stopwatch.StartNew();
        while (!peer.HandshakeComplete && sw.ElapsedMilliseconds < timeoutMs) await Task.Delay(50).ConfigureAwait(false);
        if (!peer.HandshakeComplete) return false;

        await peer.BroadcastAsync(rawTx).ConfigureAwait(false);
        var remaining = (int)Math.Max(1000, timeoutMs - sw.ElapsedMilliseconds);
        var done = await Task.WhenAny(pulled.Task, Task.Delay(remaining)).ConfigureAwait(false);
        return done == pulled.Task && pulled.Task.Result;
    }

    /// <summary>Broadcast to several peers in parallel; true if at least one pulled the tx. Pure P2P
    /// gossip — no single peer is a dependency.</summary>
    public static async Task<bool> BroadcastToManyAsync(BsvNet net, IEnumerable<(string host, int port)> peers, byte[] rawTx, int timeoutMs = 15000)
    {
        var results = await Task.WhenAll(peers.Select(p => Safe(net, p.host, p.port, rawTx, timeoutMs))).ConfigureAwait(false);
        return results.Any(r => r);
    }

    private static async Task<bool> Safe(BsvNet net, string host, int port, byte[] rawTx, int timeoutMs)
    {
        try { return await BroadcastAsync(net, host, port, rawTx, timeoutMs).ConfigureAwait(false); }
        catch { return false; }
    }
}
