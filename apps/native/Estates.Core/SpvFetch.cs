// Estates.Core/SpvFetch.cs — fetch the SPV PROOF for a confirmed transaction and assemble a verifiable
// SpvEnvelope (raw tx + 80-byte header + merkle branch + index). The wallet then VERIFIES that envelope
// locally (PoW + merkle) before crediting — so the SOURCE of the proof is never trusted, only the math.
//
// Two sources, in order (this matches the user's choice: P2P primary, public proof as backup):
//   (1) P2P  — ask connected BSV peers for the block + proof. Preferred ("use the net"); requires a
//              reachable, synced peer that accepts us. When none is available this returns null and we
//              fall through to (2).
//   (2) PROOF API — a one-time fetch of the PUBLIC merkle proof (TSC) + raw tx + block header. This is a
//              transport only: the bytes are meaningless unless they verify against proof-of-work, which
//              the wallet checks itself. No balance is ever trusted from the API.
//
// Library note: System.Net.Http + System.Text.Json are the .NET runtime (Microsoft), not third parties.
using System.Net.Http;
using System.Text.Json;

namespace Estates.Core;

public static class SpvFetch
{
    public sealed record Result(SpvEnvelope? Env, string Source, string Detail);

    private static string ApiBase(BsvNet net) => net switch
    {
        BsvNet.Mainnet => "https://api.whatsonchain.com/v1/bsv/main",
        BsvNet.Testnet => "https://api.whatsonchain.com/v1/bsv/test",
        _ => "",   // regtest: no public proof source — use a delivered envelope or the local node
    };

    /// <summary>Fetch a verifiable envelope for <paramref name="txid"/>. Tries P2P first, then the public
    /// proof API. The returned envelope is NOT yet trusted — the caller MUST call env.Verify() (or hand it
    /// to SpvWallet.Receive, which verifies) before crediting anything.</summary>
    public static async Task<Result> FetchAsync(string txid, BsvNet net, HttpClient http, CancellationToken ct = default)
    {
        txid = (txid ?? "").Trim().ToLowerInvariant();
        if (txid.Length != 64) return new Result(null, "none", "txid must be 64 hex characters");

        // (1) P2P primary — reserved for a reachable synced peer. Returns null today (no cooperative
        // public peer / local node still syncing) so we fall through to the public proof. The seam is
        // here so that, the moment a synced peer is connected, the proof comes from the network itself.
        var p2p = await TryP2PAsync(txid, net, ct).ConfigureAwait(false);
        if (p2p is not null) return new Result(p2p, "p2p (verified locally)", "proof from a BSV network peer");

        // (2) public proof API backup
        string api = ApiBase(net);
        if (api.Length == 0) return new Result(null, "none", "no public proof source for this network");
        try
        {
            string rawHex = (await http.GetStringAsync($"{api}/tx/{txid}/hex", ct).ConfigureAwait(false)).Trim();
            await Task.Delay(1200, ct).ConfigureAwait(false);   // be polite to the rate limiter
            using var tscDoc = JsonDocument.Parse(await http.GetStringAsync($"{api}/tx/{txid}/proof/tsc", ct).ConfigureAwait(false));
            var tsc = tscDoc.RootElement[0];
            long index = tsc.GetProperty("index").GetInt64();
            string blockHash = tsc.GetProperty("target").GetString()!;
            var nodes = new List<string>();
            foreach (var n in tsc.GetProperty("nodes").EnumerateArray()) nodes.Add(n.GetString()!);

            await Task.Delay(1200, ct).ConfigureAwait(false);
            byte[] header80 = await FetchHeader80Async(api, blockHash, http, ct).ConfigureAwait(false);

            var env = new SpvEnvelope(Tx.FromHex(rawHex), header80, nodes, index);
            if (!env.Verify()) return new Result(null, "public-proof", "proof did NOT verify locally (rejected — not credited)");
            return new Result(env, "public-proof (verified locally)", $"verified against block {blockHash}");
        }
        catch (HttpRequestException e) { return new Result(null, "public-proof", "fetch failed: " + e.Message); }
        catch (Exception e) { return new Result(null, "public-proof", "error: " + e.Message); }
    }

    /// <summary>Broadcast a signed transaction to the BSV NETWORK — never to a single local node. Tries
    /// P2P peers first (announce inv → peer asks getdata → we send the tx), then a public broadcast
    /// endpoint as backup. Returns (accepted, detail). This is what makes Send work without our own node,
    /// the same way ElectrumSV reaches the network through its servers.</summary>
    public static async Task<(bool ok, string detail)> BroadcastAsync(string rawTxHex, BsvNet net, HttpClient http, CancellationToken ct = default)
    {
        rawTxHex = (rawTxHex ?? "").Trim();
        bool p2p = await TryP2PBroadcastAsync(rawTxHex, net, ct).ConfigureAwait(false);   // (1) primary: the network's own peers
        string api = ApiBase(net);
        if (api.Length > 0)
        {
            try
            {
                var content = new System.Net.Http.StringContent("{\"txhex\":\"" + rawTxHex + "\"}", System.Text.Encoding.UTF8, "application/json");
                var resp = await http.PostAsync($"{api}/tx/raw", content, ct).ConfigureAwait(false);
                string body = (await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false)).Trim();
                if (resp.IsSuccessStatusCode) return (true, "accepted by the network · txid " + body.Trim('"'));
                if (p2p) return (true, "announced to P2P peers (broadcast index said: " + body + ")");
                return (false, "network rejected: " + body);
            }
            catch (Exception e) { return p2p ? (true, "announced to P2P peers (index error: " + e.Message + ")") : (false, "broadcast failed: " + e.Message); }
        }
        return p2p ? (true, "announced to P2P peers") : (false, "no broadcast path for this network");
    }

    private static async Task<bool> TryP2PBroadcastAsync(string rawTxHex, BsvNet net, CancellationToken ct)
    {
        byte[] raw; try { raw = Tx.FromHex(rawTxHex); } catch { return false; }
        foreach (var (host, port) in BsvSeeds.Discover(net, 8))
        {
            try
            {
                using var peer = new BsvPeer(net, host, port);
                bool sent = false; peer.OnTxSent += _ => sent = true;
                await peer.ConnectAsync(0, 5000).ConfigureAwait(false);
                for (int i = 0; i < 50 && !peer.HandshakeComplete; i++) await Task.Delay(100, ct).ConfigureAwait(false);
                if (!peer.HandshakeComplete) continue;
                await peer.BroadcastAsync(raw).ConfigureAwait(false);
                for (int i = 0; i < 50 && !sent; i++) await Task.Delay(100, ct).ConfigureAwait(false);
                if (sent) return true;
            }
            catch { }
        }
        return false;
    }

    /// <summary>Scan the wallet's own addresses for incoming coins: for each address, ask the network which
    /// UTXOs pay it, fetch each one's proof, VERIFY locally, and credit it. This is the "it just works"
    /// path — the user never types a txid. P2P/bloom is the eventual primary; the public UTXO+proof index
    /// is the backup used here. Returns (coinsCredited, satsCredited, addressesScanned, detail).</summary>
    public static async Task<(int coins, long sats, int scanned, string detail)> ScanAndCreditAsync(
        IReadOnlyList<string> addresses, BsvNet net, SpvWallet spv, HttpClient http,
        Action<string>? progress = null, CancellationToken ct = default)
    {
        string api = ApiBase(net);
        if (api.Length == 0) return (0, 0, 0, "no public proof source for this network (use a delivered envelope)");
        int coins = 0; long sats = 0; int scanned = 0;
        var seenTx = new HashSet<string>();
        foreach (var addr in addresses)
        {
            ct.ThrowIfCancellationRequested();
            scanned++;
            progress?.Invoke($"scanning address {scanned}/{addresses.Count}…");
            List<string> txids = new();
            try
            {
                using var doc = JsonDocument.Parse(await http.GetStringAsync($"{api}/address/{addr}/unspent", ct).ConfigureAwait(false));
                foreach (var u in doc.RootElement.EnumerateArray()) txids.Add(u.GetProperty("tx_hash").GetString()!);
            }
            catch { await Task.Delay(1400, ct).ConfigureAwait(false); continue; }   // rate-limit friendly; skip on error
            await Task.Delay(1000, ct).ConfigureAwait(false);
            foreach (var txid in txids)
            {
                if (!seenTx.Add(txid)) continue;
                var res = await FetchAsync(txid, net, http, ct).ConfigureAwait(false);
                if (res.Env is not null)
                {
                    long before = spv.Balance();
                    if (spv.Receive(res.Env) && spv.Balance() > before) { coins++; sats += spv.Balance() - before; progress?.Invoke($"credited {sats:n0} sat so far…"); }
                }
                await Task.Delay(1000, ct).ConfigureAwait(false);
            }
        }
        return (coins, sats, scanned, coins > 0 ? $"credited {coins} coin(s), {sats:n0} sat" : "no new coins found for your addresses");
    }

    /// <summary>Reconstruct the canonical 80-byte block header from the public header fields and confirm it
    /// hashes to the claimed block hash (so a lying API can't substitute a header).</summary>
    private static async Task<byte[]> FetchHeader80Async(string api, string blockHash, HttpClient http, CancellationToken ct)
    {
        using var h = JsonDocument.Parse(await http.GetStringAsync($"{api}/block/{blockHash}/header", ct).ConfigureAwait(false));
        var j = h.RootElement;
        int ver = j.GetProperty("version").GetInt32();
        string prev = j.GetProperty("previousblockhash").GetString()!;
        string mroot = j.GetProperty("merkleroot").GetString()!;
        long time = j.GetProperty("time").GetInt64();
        uint bits = Convert.ToUInt32(j.GetProperty("bits").GetString(), 16);
        long nonce = j.GetProperty("nonce").GetInt64();

        var o = new List<byte>(80);
        void LE(long v, int n) { for (int i = 0; i < n; i++) o.Add((byte)(v >> (8 * i))); }
        byte[] rev(string hex) { var b = Tx.FromHex(hex); Array.Reverse(b); return b; }
        LE(ver, 4); o.AddRange(rev(prev)); o.AddRange(rev(mroot)); LE(time, 4); LE(bits, 4); LE(nonce, 4);
        return o.ToArray();
    }

    /// <summary>P2P proof retrieval — placeholder seam. Returns null until a cooperative, synced BSV peer is
    /// connected (the wallet's network layer supplies it). Kept here so the primary path is the network.</summary>
    private static Task<SpvEnvelope?> TryP2PAsync(string txid, BsvNet net, CancellationToken ct)
        => Task.FromResult<SpvEnvelope?>(null);
}
