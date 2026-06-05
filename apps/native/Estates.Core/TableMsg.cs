// Estates.Core/TableMsg.cs — canonical signed-frame bytes for table gameplay
// messages, byte-for-byte with @estates/table. A message signature covers
// signedBytes(msg, signPub) = JSON({...msg, signPub}); the native client re-derives
// those exact bytes and Ed25519-verifies, so it authenticates the SAME web frames.
using System.Globalization;
using System.Text;

namespace Estates.Core;

public static class TableMsg
{
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
