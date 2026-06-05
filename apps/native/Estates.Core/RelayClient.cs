// Estates.Core/RelayClient.cs — native client for the ESTATES relay (the same
// untrusted HTTP fan-out the web app uses). Speaks the exact wire format:
//   POST /publish/{channel}   text/plain body = hex(frame)   — append + fan out
//   GET  /history/{channel}   -> text/plain, hex frames joined by '\n'  — catch-up
// Loopback only; the default relay needs no token. This lets a native client read
// the live game stream and publish its own signed frames (toward native multiplayer).
using System.Net.Http;
using System.Text;

namespace Estates.Core;

public sealed class RelayClient
{
    private readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };
    private readonly string _base;

    public RelayClient(string baseUrl = "http://127.0.0.1:8788") => _base = baseUrl.TrimEnd('/');

    /// <summary>Append a frame (opaque bytes) to a channel's ordered log.</summary>
    public async Task PublishAsync(string channel, byte[] frame)
    {
        var content = new StringContent(Tx.ToHex(frame), Encoding.ASCII, "text/plain");
        var resp = await _http.PostAsync($"{_base}/publish/{channel}", content);
        resp.EnsureSuccessStatusCode();
    }

    /// <summary>The channel's ordered log as frame byte arrays (history catch-up).
    /// Returns an empty list if the channel has no log yet (503).</summary>
    public async Task<List<byte[]>> HistoryAsync(string channel)
    {
        var resp = await _http.GetAsync($"{_base}/history/{channel}");
        if (resp.StatusCode == System.Net.HttpStatusCode.ServiceUnavailable) return new();
        resp.EnsureSuccessStatusCode();
        string body = await resp.Content.ReadAsStringAsync();
        var frames = new List<byte[]>();
        foreach (var line in body.Split('\n', StringSplitOptions.RemoveEmptyEntries))
            frames.Add(Tx.FromHex(line.Trim()));
        return frames;
    }

    /// <summary>True iff the relay answers (used to skip live checks when it's down).</summary>
    public async Task<bool> ReachableAsync()
    {
        try { var r = await _http.GetAsync($"{_base}/history/__ping__"); return (int)r.StatusCode is 200 or 503; }
        catch { return false; }
    }
}
