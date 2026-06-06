// Estates.Core/NodeRpc.cs — a real JSON-RPC client to YOUR Bitcoin SV node (the
// separate node; ESTATES never bundles one). Every wallet balance, address, send,
// signature and broadcast goes through here to the live chain — nothing is mocked.
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Estates.Core;

public sealed class NodeRpc
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };
    private readonly string _url;

    public NodeRpc(string url, string user, string pass)
    {
        _url = url;
        var b = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{user}:{pass}"));
        _http.DefaultRequestHeaders.Authorization = new("Basic", b);
    }

    /// <summary>The default regtest node (the user's own estates-bsv container).</summary>
    public static NodeRpc Regtest() => new("http://127.0.0.1:18443/", "e", "e");

    /// <summary>Call an RPC method; throws with the node's error text on failure.</summary>
    public JsonElement Call(string method, params object[] prms)
    {
        var body = JsonSerializer.Serialize(new { jsonrpc = "1.0", id = "estates", method, @params = prms });
        using var resp = _http.PostAsync(_url, new StringContent(body, Encoding.UTF8, "text/plain")).GetAwaiter().GetResult();
        var txt = resp.Content.ReadAsStringAsync().GetAwaiter().GetResult();
        using var doc = JsonDocument.Parse(txt);
        var root = doc.RootElement;
        if (root.TryGetProperty("error", out var err) && err.ValueKind != JsonValueKind.Null)
            throw new InvalidOperationException(err.ToString());
        return root.GetProperty("result").Clone();
    }

    public bool Reachable(out string info)
    {
        try { var r = Call("getblockchaininfo"); info = $"{r.GetProperty("chain").GetString()} · block {r.GetProperty("blocks").GetInt64()}"; return true; }
        catch (Exception e) { info = e.Message; return false; }
    }

    // ---- wallet operations (real, on-chain) ------------------------------------------
    public decimal GetBalance() => Call("getbalance").GetDecimal();
    public string GetNewAddress() => Call("getnewaddress").GetString()!;
    public string SendToAddress(string address, decimal amount) => Call("sendtoaddress", address, amount).GetString()!;
    public string SignMessage(string address, string message) => Call("signmessage", address, message).GetString()!;
    public bool VerifyMessage(string address, string signature, string message) => Call("verifymessage", address, signature, message).GetBoolean();
    public string SendRawTransaction(string rawHex) => Call("sendrawtransaction", rawHex).GetString()!;
    public JsonElement DecodeRawTransaction(string rawHex) => Call("decoderawtransaction", rawHex);
    public long GetBlockCount() => Call("getblockcount").GetInt64();

    /// <summary>Spendable UTXOs of the node wallet (txid, vout, amount BSV, scriptPubKey hex).</summary>
    public List<(string txid, long vout, decimal amount, string scriptPubKey)> ListUnspent()
    {
        var outp = new List<(string, long, decimal, string)>();
        foreach (var u in Call("listunspent", 0).EnumerateArray())   // minconf 0: include unconfirmed change so moves can chain
            outp.Add((u.GetProperty("txid").GetString()!, u.GetProperty("vout").GetInt64(),
                      u.GetProperty("amount").GetDecimal(), u.GetProperty("scriptPubKey").GetString()!));
        return outp;
    }

    /// <summary>Sign a raw tx with the node wallet; returns the signed hex (BSV legacy RPC).</summary>
    public string SignRaw(string rawHex) => Call("signrawtransaction", rawHex).GetProperty("hex").GetString()!;
}
