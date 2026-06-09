// Estates.Core/SpvFetch.cs — 100% REAL-NODE P2P. NO HTTP, NO explorer, NO WhatsOnChain, NO faucet.
// Everything is obtained from real BSV nodes over the Bitcoin P2P protocol:
//   * BROADCAST  — announce the signed tx (inv) and hand it over when the node asks (getdata → tx).
//   * RECEIVE    — sync the header chain (getheaders) from a real node, pull real full blocks (getdata),
//                  find outputs paying our addresses, build each coin's merkle proof from the block, and
//                  credit it. Every proof is verified LOCALLY (proof-of-work + merkle), so the node is
//                  never trusted — only the mathematics. A node is just a peer that serves bytes.
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;

namespace Estates.Core;

public static class SpvFetch
{
    // ----- BROADCAST: real nodes only. Returns once a real node has asked for and received the tx. -----
    public static async Task<(bool ok, string detail)> BroadcastAsync(string rawTxHex, BsvNet net, CancellationToken ct = default)
    {
        byte[] raw; try { raw = Tx.FromHex((rawTxHex ?? "").Trim()); } catch { return (false, "bad tx hex"); }
        string txid; try { var p = Tx.Parse(raw); if (p is null) return (false, "unparseable tx"); txid = Tx.Txid(p); } catch { return (false, "unparseable tx"); }
        int accepted = 0; var who = new List<string>();
        foreach (var (host, port) in BsvSeeds.Discover(net, 10))
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var peer = new BsvPeer(net, host, port);
                bool sent = false; peer.OnTxSent += _ => sent = true;
                await peer.ConnectAsync(0, 6000).ConfigureAwait(false);
                for (int i = 0; i < 60 && !peer.HandshakeComplete; i++) await Task.Delay(100, ct).ConfigureAwait(false);
                if (!peer.HandshakeComplete) continue;
                await peer.BroadcastAsync(raw).ConfigureAwait(false);             // inv; node replies getdata; we send tx
                for (int i = 0; i < 60 && !sent; i++) await Task.Delay(100, ct).ConfigureAwait(false);
                if (sent) { accepted++; who.Add(host); }
                if (accepted >= 3) break;                                          // 3 independent real nodes have it
            }
            catch { }
        }
        return accepted > 0
            ? (true, $"accepted by {accepted} real BSV node(s): {string.Join(", ", who)} · txid {txid}")
            : (false, "no real BSV node accepted the transaction");
    }

    // ----- RECEIVE: scan real blocks (P2P) for coins paying our addresses; verify + credit locally. -----
    public static async Task<(int coins, long sats, string detail)> ScanAndCreditAsync(
        IReadOnlyList<string> addresses, BsvNet net, SpvWallet spv, int window = 256,
        Action<string>? progress = null, CancellationToken ct = default)
    {
        var owned = new HashSet<string>();
        foreach (var a in addresses) { var pkh = Base58.CheckDecode(a, out _); if (pkh is { Length: 20 }) owned.Add(Tx.ToHex(NodeWallet.P2pkhScript(pkh))); }
        if (owned.Count == 0) return (0, 0, "no valid addresses to scan");

        foreach (var (host, port) in BsvSeeds.Discover(net, 6))
        {
            if (ct.IsCancellationRequested) break;
            try
            {
                using var peer = new BsvPeer(net, host, port);
                var headers = new List<byte[]>();
                var blocks = new Dictionary<string, byte[]>();
                TaskCompletionSource<bool> batch = new();
                peer.OnHeaders += hs => { lock (headers) headers.AddRange(hs); batch.TrySetResult(true); };
                peer.OnBlock += b => { var p = Block.Parse(b); if (p is not null) lock (blocks) blocks[p.BlockHash] = b; };

                await peer.ConnectAsync(0, 6000).ConfigureAwait(false);
                for (int i = 0; i < 60 && !peer.HandshakeComplete; i++) await Task.Delay(100, ct).ConfigureAwait(false);
                if (!peer.HandshakeComplete) continue;
                progress?.Invoke($"syncing headers from real node {host}…");

                byte[] genesisInternal = GenesisHashInternal(net);
                byte[] locator = genesisInternal;
                for (int guard = 0; guard < 4000; guard++)
                {
                    if (ct.IsCancellationRequested) break;
                    int before; lock (headers) before = headers.Count;
                    batch = new TaskCompletionSource<bool>();
                    await peer.RequestHeadersAsync(new[] { locator }).ConfigureAwait(false);
                    var done = await Task.WhenAny(batch.Task, Task.Delay(8000, ct)).ConfigureAwait(false);
                    int after; byte[] last; lock (headers) { after = headers.Count; last = after > 0 ? headers[^1] : genesisInternal; }
                    if (done != batch.Task || after == before) break;             // timeout or no progress → caught up
                    locator = Tx.Hash256(last);                                    // internal-order hash of the tip header
                    if (after - before < 2000) break;                             // last (partial) batch → at tip
                    if ((after & 0x3FFF) == 0) progress?.Invoke($"headers {after}…");
                }
                int total = headers.Count;
                if (total == 0) continue;

                int start = System.Math.Max(0, total - window);
                var hashes = new List<string>();
                for (int i = start; i < total; i++) hashes.Add(Block.HashOf(headers[i]));
                progress?.Invoke($"have {total} headers; pulling {hashes.Count} real blocks…");
                await peer.RequestBlocks(hashes).ConfigureAwait(false);
                for (int i = 0; i < 300; i++) { int got; lock (blocks) got = blocks.Count; if (got >= hashes.Count) break; await Task.Delay(100, ct).ConfigureAwait(false); }

                int coins = 0; long sats = 0;
                List<byte[]> raws; lock (blocks) raws = new List<byte[]>(blocks.Values);
                foreach (var rb in raws)
                {
                    var pb = Block.Parse(rb); if (pb is null) continue;
                    var txids = new List<string>(pb.Txs.Count); foreach (var t in pb.Txs) txids.Add(Tx.Txid(t));
                    for (int vi = 0; vi < pb.Txs.Count; vi++)
                    {
                        var tx = pb.Txs[vi];
                        bool mine = false; foreach (var o in tx.Outputs) if (owned.Contains(Tx.ToHex(o.Script))) { mine = true; break; }
                        if (!mine) continue;
                        var br = BlockMerkle.BranchFor(txids, txids[vi]); if (br is null) continue;
                        var env = new SpvEnvelope(Tx.Serialize(tx), pb.Header80, br.Value.branch, br.Value.index);
                        long pre = spv.Balance();
                        if (spv.Receive(env) && spv.Balance() > pre) { coins++; sats += spv.Balance() - pre; }
                    }
                }
                return (coins, sats, coins > 0
                    ? $"credited {coins} coin(s), {sats:n0} sat from real blocks via {host}"
                    : $"scanned {hashes.Count} real blocks via {host}; no coins for your addresses in that window");
            }
            catch { }
        }
        return (0, 0, "could not reach a real BSV node to scan");
    }

    // genesis block hash, INTERNAL byte order (for a getheaders locator)
    private static byte[] GenesisHashInternal(BsvNet net)
    {
        string disp = net switch
        {
            BsvNet.Mainnet => "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f",
            BsvNet.Testnet => "000000000933ea01ad0ee984209779baaec3ced90fa3f408719526f8d77f4943",
            _ => "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",   // regtest
        };
        var b = Tx.FromHex(disp); System.Array.Reverse(b); return b;
    }
}
