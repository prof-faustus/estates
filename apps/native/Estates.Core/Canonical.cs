// Estates.Core/Canonical.cs — the byte-exact state-hash oracle.
//
// Reproduces @estates/conformance hashState EXACTLY:
//   hashState(s) = sha256_hex( stable( canonicalState(s) ) )
// where canonicalState drops the advisory `log`, and stable() is key-sorted
// (lexicographic / ordinal) JSON with JSON.stringify value semantics. Any
// deviation here would make the native engine diverge from the audited TS
// reference, so this mirrors stable() character-for-character.
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Estates.Core;

public static class Canonical
{
    /// <summary>Canonical key-sorted JSON of (state minus log).</summary>
    public static string Stable(GameState s)
    {
        var sb = new StringBuilder();
        Write(sb, ToTree(s));
        return sb.ToString();
    }

    public static string HashState(GameState s)
    {
        byte[] hash = SHA256.HashData(Encoding.UTF8.GetBytes(Stable(s)));
        var hex = new StringBuilder(hash.Length * 2);
        foreach (var b in hash) hex.Append(b.ToString("x2", CultureInfo.InvariantCulture));
        return hex.ToString();
    }

    // Build the exact tree canonicalState(s) would produce (no `log`).
    private static Dictionary<string, object?> ToTree(GameState s)
    {
        var seats = new List<object?>();
        foreach (var x in s.Seats)
            seats.Add(new Dictionary<string, object?>
            {
                ["id"] = (long)x.Id,
                ["balance"] = x.Balance,
                ["position"] = (long)x.Position,
                ["inHolding"] = x.InHolding,
                ["holdingTurns"] = (long)x.HoldingTurns,
                ["reprieveCards"] = (long)x.ReprieveCards,
                ["bankrupt"] = x.Bankrupt,
            });

        var titles = new Dictionary<string, object?>();
        foreach (var kv in s.Titles)
            titles[kv.Key.ToString(CultureInfo.InvariantCulture)] = new Dictionary<string, object?>
            {
                ["owner"] = kv.Value.Owner is null ? null : (long)kv.Value.Owner.Value,
                ["buildLevel"] = (long)kv.Value.BuildLevel,
                ["mortgaged"] = kv.Value.Mortgaged,
            };

        var deckCursor = new Dictionary<string, object?>();
        foreach (var kv in s.DeckCursor) deckCursor[kv.Key] = (long)kv.Value;

        var tree = new Dictionary<string, object?>
        {
            ["network"] = s.Network,
            ["seats"] = seats,
            ["titles"] = titles,
            ["bankReserve"] = s.BankReserve,
            ["housesRemaining"] = s.HousesRemaining,
            ["estatesRemaining"] = s.EstatesRemaining,
            ["current"] = (long)s.Current,
            ["phase"] = s.Phase,
            ["turnIndex"] = (long)s.TurnIndex,
            ["doublesPending"] = s.DoublesPending,
            ["doublesCount"] = (long)s.DoublesCount,
            ["deckCursor"] = deckCursor,
            ["lastRoll"] = s.LastRoll is null ? null : new List<object?> { (long)s.LastRoll[0], (long)s.LastRoll[1] },
            ["pendingTitle"] = s.PendingTitle is null ? null : (long)s.PendingTitle.Value,
            ["winner"] = s.Winner is null ? null : (long)s.Winner.Value,
        };
        // deckOrder is present in the canonical form ONLY when the state carries it.
        if (s.DeckOrder is not null)
        {
            var dord = new Dictionary<string, object?>();
            foreach (var kv in s.DeckOrder) dord[kv.Key] = kv.Value.Select(i => (object?)(long)i).ToList();
            tree["deckOrder"] = dord;
        }
        return tree;
    }

    // stable(value): null/scalar -> JSON.stringify; array -> ordered; object ->
    // keys sorted ordinal (matches JS Array.prototype.sort default on ASCII keys).
    private static void Write(StringBuilder sb, object? node)
    {
        switch (node)
        {
            case null: sb.Append("null"); break;
            case bool b: sb.Append(b ? "true" : "false"); break;
            case long l: sb.Append(l.ToString(CultureInfo.InvariantCulture)); break;
            case int i: sb.Append(i.ToString(CultureInfo.InvariantCulture)); break;
            case string str: WriteString(sb, str); break;
            case List<object?> arr:
                sb.Append('[');
                for (int k = 0; k < arr.Count; k++) { if (k > 0) sb.Append(','); Write(sb, arr[k]); }
                sb.Append(']');
                break;
            case Dictionary<string, object?> obj:
                sb.Append('{');
                var keys = obj.Keys.ToList();
                keys.Sort(StringComparer.Ordinal);
                for (int k = 0; k < keys.Count; k++)
                {
                    if (k > 0) sb.Append(',');
                    WriteString(sb, keys[k]); sb.Append(':'); Write(sb, obj[keys[k]]);
                }
                sb.Append('}');
                break;
            default: throw new InvalidOperationException($"non-canonical node type {node.GetType()}");
        }
    }

    // JSON.stringify string semantics: escape ", \\, and control chars (<0x20);
    // short forms for \b \t \n \f \r; non-ASCII passed through unescaped. Our
    // state strings are simple ASCII, but this is exact for robustness.
    private static void WriteString(StringBuilder sb, string s)
    {
        sb.Append('"');
        foreach (char c in s)
        {
            switch (c)
            {
                case '"': sb.Append("\\\""); break;
                case '\\': sb.Append("\\\\"); break;
                case '\b': sb.Append("\\b"); break;
                case '\t': sb.Append("\\t"); break;
                case '\n': sb.Append("\\n"); break;
                case '\f': sb.Append("\\f"); break;
                case '\r': sb.Append("\\r"); break;
                default:
                    if (c < 0x20) sb.Append("\\u").Append(((int)c).ToString("x4", CultureInfo.InvariantCulture));
                    else sb.Append(c);
                    break;
            }
        }
        sb.Append('"');
    }
}
