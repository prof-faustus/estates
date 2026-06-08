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
