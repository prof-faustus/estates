// Estates.Core/StateJson.cs — parse a GameState / Action from JSON.
//
// Used to load conformance-vector states (and, at runtime, states/actions that
// arrive over the wire) into the native types. Mirrors the TS field names.
using System.Text.Json;

namespace Estates.Core;

public static class StateJson
{
    public static GameState ParseState(JsonElement e)
    {
        var g = new GameState
        {
            Network = e.GetProperty("network").GetString()!,
            BankReserve = e.GetProperty("bankReserve").GetInt64(),
            HousesRemaining = e.GetProperty("housesRemaining").GetInt64(),
            EstatesRemaining = e.GetProperty("estatesRemaining").GetInt64(),
            Current = e.GetProperty("current").GetInt32(),
            Phase = e.GetProperty("phase").GetString()!,
            TurnIndex = e.GetProperty("turnIndex").GetInt32(),
            DoublesPending = e.GetProperty("doublesPending").GetBoolean(),
            DoublesCount = e.GetProperty("doublesCount").GetInt32(),
        };

        foreach (var s in e.GetProperty("seats").EnumerateArray())
            g.Seats.Add(new Seat
            {
                Id = s.GetProperty("id").GetInt32(),
                Balance = s.GetProperty("balance").GetInt64(),
                Position = s.GetProperty("position").GetInt32(),
                InHolding = s.GetProperty("inHolding").GetBoolean(),
                HoldingTurns = s.GetProperty("holdingTurns").GetInt32(),
                ReprieveCards = s.GetProperty("reprieveCards").GetInt32(),
                Bankrupt = s.GetProperty("bankrupt").GetBoolean(),
            });

        foreach (var t in e.GetProperty("titles").EnumerateObject())
        {
            var ownerEl = t.Value.GetProperty("owner");
            g.Titles[int.Parse(t.Name)] = new Title
            {
                Owner = ownerEl.ValueKind == JsonValueKind.Null ? null : ownerEl.GetInt32(),
                BuildLevel = t.Value.GetProperty("buildLevel").GetInt32(),
                Mortgaged = t.Value.GetProperty("mortgaged").GetBoolean(),
            };
        }

        foreach (var dc in e.GetProperty("deckCursor").EnumerateObject())
            g.DeckCursor[dc.Name] = dc.Value.GetInt32();

        if (e.TryGetProperty("deckOrder", out var doEl) && doEl.ValueKind == JsonValueKind.Object)
        {
            g.DeckOrder = new Dictionary<string, List<int>>();
            foreach (var od in doEl.EnumerateObject())
                g.DeckOrder[od.Name] = od.Value.EnumerateArray().Select(x => x.GetInt32()).ToList();
        }

        var lr = e.GetProperty("lastRoll");
        g.LastRoll = lr.ValueKind == JsonValueKind.Null ? null
            : new[] { lr[0].GetInt32(), lr[1].GetInt32() };

        var pt = e.GetProperty("pendingTitle");
        g.PendingTitle = pt.ValueKind == JsonValueKind.Null ? null : pt.GetInt32();

        var wn = e.GetProperty("winner");
        g.Winner = wn.ValueKind == JsonValueKind.Null ? null : wn.GetInt32();

        if (e.TryGetProperty("log", out var logEl) && logEl.ValueKind == JsonValueKind.Array)
            foreach (var ln in logEl.EnumerateArray()) g.Log.Add(ln.GetString() ?? "");

        return g;
    }

    public static Action ParseAction(JsonElement e)
    {
        string type = e.GetProperty("type").GetString()!;
        return new Action(type)
        {
            Dice = e.TryGetProperty("dice", out var d) && d.ValueKind == JsonValueKind.Array
                ? new[] { d[0].GetInt32(), d[1].GetInt32() } : null,
            Choice = e.TryGetProperty("choice", out var c) ? c.GetString() : null,
            PropertyId = e.TryGetProperty("propertyId", out var p) ? p.GetInt32() : 0,
            SeatIndex = e.TryGetProperty("seat", out var st) ? st.GetInt32() : 0,
        };
    }
}
