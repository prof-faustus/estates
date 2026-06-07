// Estates.Core/SpvSync.cs — fetch SPV envelopes for an address's coins from a BSV mining node and
// credit them to an SpvWallet. The wallet asks a miner for the proof of its OWN coins (getrawtransaction
// + getblock tx-list + getblockheader → BlockMerkle branch), verifies them locally, and stores them.
// No scanning, no full block, no header chain — the wallet stays SPV. Used for regtest/testnet bring-up
// where the funder pays the wallet address and the wallet pulls the proof; in play, peers hand the
// envelope over IP-to-IP directly. Total: any RPC/parse failure simply credits nothing.
using System.Text.Json;
using System.Threading.Tasks;

namespace Estates.Core;

public static class SpvSync
{
    /// <summary>Pull every confirmed coin paying `address`, build its SPV envelope from the node, verify
    /// and credit it to `wallet`. Returns the number of coins credited.</summary>
    public static async Task<int> SyncAddressAsync(BsvRpc rpc, SpvWallet wallet, string address)
    {
        await rpc.CallAsync("importaddress", address, "", false).ConfigureAwait(false);   // watch-only (regtest/test bring-up)
        var utxos = await rpc.CallAsync("listunspent", 0, 99999999, new[] { address }).ConfigureAwait(false);
        if (utxos is null || utxos.Value.ValueKind != JsonValueKind.Array) return 0;

        int credited = 0;
        var blockTxids = new System.Collections.Generic.Dictionary<string, List<string>>();
        var blockHeaders = new System.Collections.Generic.Dictionary<string, byte[]>();

        foreach (var u in utxos.Value.EnumerateArray())
        {
            try
            {
                string txid = u.GetProperty("txid").GetString()!;
                var rawTxEl = await rpc.CallAsync("getrawtransaction", txid, true).ConfigureAwait(false);
                if (rawTxEl is null) continue;
                string hex = rawTxEl.Value.GetProperty("hex").GetString()!;
                if (!rawTxEl.Value.TryGetProperty("blockhash", out var bhEl)) continue;   // unconfirmed: skip (no proof yet)
                string blockhash = bhEl.GetString()!;

                if (!blockTxids.TryGetValue(blockhash, out var txids))
                {
                    var blk = await rpc.CallAsync("getblock", blockhash, 1).ConfigureAwait(false);
                    if (blk is null) continue;
                    txids = new List<string>();
                    foreach (var t in blk.Value.GetProperty("tx").EnumerateArray()) txids.Add(t.GetString()!);
                    blockTxids[blockhash] = txids;
                    var hdrEl = await rpc.CallAsync("getblockheader", blockhash, false).ConfigureAwait(false);
                    blockHeaders[blockhash] = hdrEl is null ? System.Array.Empty<byte>() : Tx.FromHex(hdrEl.Value.GetString()!);
                }
                byte[] header80 = blockHeaders[blockhash];
                if (header80.Length != 80) continue;

                var br = BlockMerkle.BranchFor(txids, txid);
                if (br is null) continue;
                var env = new SpvEnvelope(Tx.FromHex(hex), header80, br.Value.branch, br.Value.index);
                if (wallet.Receive(env)) credited++;
            }
            catch { /* skip this coin */ }
        }
        return credited;
    }
}
