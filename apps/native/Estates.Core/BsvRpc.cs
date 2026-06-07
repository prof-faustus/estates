// Estates.Core/BsvRpc.cs — a minimal JSON-RPC client to a BSV mining node, used ONLY to fetch the SPV
// material for the wallet's OWN coins: the raw transaction, the block's transaction list, and the block
// header — i.e. "get the proof for your transaction from a mining node" (the spec's SPV source). It is
// NOT used for game state, never for consensus; the wallet stays SPV. Total: every call returns null on
// any error (never throws).
using System.Net.Http;
using System.Text;
using System.Text.Json;

namespace Estates.Core;

public sealed class BsvRpc : System.IDisposable
{
    private readonly HttpClient _http = new();
    private readonly string _url;

    public BsvRpc(string host, int port, string user, string pass)
    {
        _url = $"http://{host}:{port}/";
        var auth = System.Convert.ToBase64String(Encoding.ASCII.GetBytes(user + ":" + pass));
        _http.DefaultRequestHeaders.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", auth);
        _http.Timeout = System.TimeSpan.FromSeconds(10);
    }

    /// <summary>Call a method; returns the JSON `result` (cloned, so it outlives the document) or null.</summary>
    public async System.Threading.Tasks.Task<JsonElement?> CallAsync(string method, params object[] prms)
    {
        try
        {
            var sb = new StringBuilder("[");
            for (int i = 0; i < prms.Length; i++) { if (i > 0) sb.Append(','); sb.Append(JsonArg(prms[i])); }
            sb.Append(']');
            string body = "{\"jsonrpc\":\"1.0\",\"id\":\"e\",\"method\":\"" + method + "\",\"params\":" + sb + "}";
            var resp = await _http.PostAsync(_url, new StringContent(body, Encoding.UTF8, "text/plain")).ConfigureAwait(false);
            var txt = await resp.Content.ReadAsStringAsync().ConfigureAwait(false);
            using var doc = JsonDocument.Parse(txt);
            if (doc.RootElement.TryGetProperty("result", out var r) && r.ValueKind != JsonValueKind.Null) return r.Clone();
            return null;
        }
        catch { return null; }
    }

    private static string JsonArg(object o) => o switch
    {
        string s => "\"" + s.Replace("\\", "\\\\").Replace("\"", "\\\"") + "\"",
        bool b => b ? "true" : "false",
        double d => d.ToString(System.Globalization.CultureInfo.InvariantCulture),
        decimal m => m.ToString(System.Globalization.CultureInfo.InvariantCulture),
        string[] a => "[" + string.Join(",", System.Array.ConvertAll(a, x => "\"" + x + "\"")) + "]",
        _ => o.ToString()!
    };

    public void Dispose() { try { _http.Dispose(); } catch { } }
}
