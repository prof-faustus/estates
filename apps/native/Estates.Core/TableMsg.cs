// Estates.Core/TableMsg.cs — canonical signed-frame bytes for table gameplay
// messages, byte-for-byte with @estates/table. A message signature covers
// signedBytes(msg, signPub) = JSON({...msg, signPub}); the native client re-derives
// those exact bytes and Ed25519-verifies, so it authenticates the SAME web frames.
using System.Globalization;
using System.Text;
using System.Text.Json;

namespace Estates.Core;

public static class TableMsg
{
    // JSON string (our values are simple ASCII; matches JSON.stringify escaping).
    private static void Str(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            if (c == '"') sb.Append("\\\"");
            else if (c == '\\') sb.Append("\\\\");
            else if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
            else sb.Append(c);
        }
        sb.Append('"');
    }

    /// <summary>The canonical signedBytes = JSON({...msg, signPub}) for ANY table
    /// message kind, with the EXACT field order @estates/table builds — so the
    /// native replay can verify every frame in the live log. Throws on unknown kind.</summary>
    public static byte[] SignedBytes(JsonElement msg, string signPub)
    {
        string kind = msg.GetProperty("kind").GetString()!;
        var sb = new StringBuilder();
        sb.Append("{\"kind\":"); Str(sb, kind);
        switch (kind)
        {
            case "table":
                sb.Append(",\"maxSeats\":").Append(msg.GetProperty("maxSeats").GetInt32());
                sb.Append(",\"network\":"); Str(sb, msg.GetProperty("network").GetString()!);
                sb.Append(",\"host\":"); Str(sb, msg.GetProperty("host").GetString()!);
                break;
            case "seat":
                sb.Append(",\"seat\":").Append(msg.GetProperty("seat").GetInt32());
                sb.Append(",\"who\":"); Str(sb, msg.GetProperty("who").GetString()!);
                sb.Append(",\"name\":"); Str(sb, msg.GetProperty("name").GetString()!);
                sb.Append(",\"bot\":").Append(msg.GetProperty("bot").GetBoolean() ? "true" : "false");
                break;
            case "start":
                sb.Append(",\"by\":"); Str(sb, msg.GetProperty("by").GetString()!);
                var cfg = msg.GetProperty("config");
                sb.Append(",\"config\":{\"network\":"); Str(sb, cfg.GetProperty("network").GetString()!);
                sb.Append(",\"seatCount\":").Append(cfg.GetProperty("seatCount").GetInt32());
                sb.Append(",\"bankReserve\":").Append(cfg.GetProperty("bankReserve").GetInt64()).Append('}');
                sb.Append(",\"seatMap\":[");
                bool first = true;
                foreach (var e in msg.GetProperty("seatMap").EnumerateArray())
                {
                    if (!first) sb.Append(','); first = false;
                    sb.Append("{\"seat\":").Append(e.GetProperty("seat").GetInt32());
                    sb.Append(",\"who\":"); Str(sb, e.GetProperty("who").GetString()!); sb.Append('}');
                }
                sb.Append(']');
                break;
            case "commit":
            case "reveal":
                sb.Append(",\"roll\":").Append(msg.GetProperty("roll").GetInt32());
                sb.Append(",\"seat\":").Append(msg.GetProperty("seat").GetInt32());
                string f = kind == "commit" ? "c" : "s";
                sb.Append(",\"").Append(f).Append("\":"); Str(sb, msg.GetProperty(f).GetString()!);
                break;
            case "dcommit":
            case "dreveal":
                sb.Append(",\"seat\":").Append(msg.GetProperty("seat").GetInt32());
                string df = kind == "dcommit" ? "c" : "s";
                sb.Append(",\"").Append(df).Append("\":"); Str(sb, msg.GetProperty(df).GetString()!);
                break;
            case "action":
                sb.Append(",\"action\":").Append(ActionJson(StateJson.ParseAction(msg.GetProperty("action"))));
                break;
            case "manifest":
                // signedBytes = JSON({kind:'manifest', m:<manifest>, signPub}). The `m`
                // object was produced by the web's JSON.stringify and is byte-identical in
                // the published frame, so its raw JSON text reconstructs the signed bytes.
                sb.Append(",\"m\":").Append(msg.GetProperty("m").GetRawText());
                break;
            default:
                throw new InvalidOperationException($"unknown message kind {kind}");
        }
        sb.Append(",\"signPub\":"); Str(sb, signPub); sb.Append('}');
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>Verify any signed frame: re-derive its canonical bytes + Ed25519-verify.</summary>
    public static bool VerifyFrame(JsonElement msg, string signPub, byte[] sig)
    {
        try { return Sign.VerifyData(SignedBytes(msg, signPub), sig, Tx.FromHex(signPub)); }
        catch { return false; }
    }

    // The action object's canonical JSON (key order: type, then its one field —
    // exactly as the TS literals serialize via JSON.stringify).
    private static string ActionJson(Action a)
    {
        switch (a.Type)
        {
            case "ROLL":
                return $"{{\"type\":\"ROLL\",\"dice\":[{a.Dice![0].ToString(CultureInfo.InvariantCulture)},{a.Dice![1].ToString(CultureInfo.InvariantCulture)}]}}";
            case "PAY_TAX":
                return $"{{\"type\":\"PAY_TAX\",\"choice\":\"{a.Choice}\"}}";
            case "BUILD": case "SELL_BUILD": case "MORTGAGE": case "UNMORTGAGE":
                return $"{{\"type\":\"{a.Type}\",\"propertyId\":{a.PropertyId.ToString(CultureInfo.InvariantCulture)}}}";
            case "LEAVE":
                return $"{{\"type\":\"LEAVE\",\"seat\":{a.SeatIndex.ToString(CultureInfo.InvariantCulture)}}}";
            default: // BUY, DECLINE, FORFEIT, END_TURN — no params
                return $"{{\"type\":\"{a.Type}\"}}";
        }
    }

    /// <summary>The exact bytes an `action` frame's signature commits to:
    /// JSON({kind:'action', action:&lt;action&gt;, signPub}).</summary>
    public static byte[] SignedBytesForAction(Action action, string signPub)
        => Encoding.UTF8.GetBytes($"{{\"kind\":\"action\",\"action\":{ActionJson(action)},\"signPub\":\"{signPub}\"}}");

    /// <summary>Verify a signed `action` frame: re-derive its canonical bytes and
    /// Ed25519-verify against signPub. Total: false on malformed, never throws.</summary>
    public static bool VerifyActionFrame(Action action, string signPub, byte[] sig)
    {
        try { return Sign.VerifyData(SignedBytesForAction(action, signPub), sig, Tx.FromHex(signPub)); }
        catch { return false; }
    }
}
