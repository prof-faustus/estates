// Estates.Core/GameReplay.cs — the native REBUILD: replay a live game's ordered
// relay log into the SAME canonical state hash as the web NetTable. This is the
// read path of native multiplayer — it assembles the already-validated primitives
// (frame auth via TableMsg/Sign, the engine, the dice beacon, canonical hashing)
// into the deterministic state machine ported from @estates/table NetTable.rebuild.
// (Deck-shuffle entropy / deckOrder is a follow-up; this covers the core path:
// table/seat/start/beacon-roll/action, with full per-frame authentication.)
using System.Text;
using System.Text.Json;
using GameAction = Estates.Core.Action;

namespace Estates.Core;

public static class GameReplay
{
    /// <summary>Replay the ordered relay log (hex frames) and return the canonical
    /// state hash, or null if the game never started. Every frame is authenticated
    /// (Ed25519 over the canonical signedBytes) and bound to its seat key, exactly
    /// like the web; raw ROLL actions are dropped (dice only from the beacon).</summary>
    public static string? ReplayStateHash(IReadOnlyList<string> logHex)
    {
        int? maxSeats = null; string? host = null; bool started = false; GameState? state = null;
        var seats = new Dictionary<int, string>();          // seat -> who (= signer)
        var seatKeys = new Dictionary<int, string>();        // seat -> controlling signing pub
        var commitsBySeq = new Dictionary<long, Dictionary<int, byte[]>>();
        var revealsBySeq = new Dictionary<long, Dictionary<int, byte[]>>();
        long rollsApplied = 0; byte[] prevBeacon = Beacon.ZeroBeacon;

        void TryRoll()
        {
            while (started && state != null && state.Phase == "AWAIT_ROLL")
            {
                long seq = rollsApplied;
                var live = state.Seats.Where(q => !q.Bankrupt).Select(q => q.Id).ToList();
                if (!commitsBySeq.TryGetValue(seq, out var cm) || !revealsBySeq.TryGetValue(seq, out var rv)) break;
                if (!live.All(x => cm.ContainsKey(x) && rv.ContainsKey(x))) break;
                var commits = live.Select(x => new Commitment(x, cm[x])).ToList();
                var reveals = live.Select(x => new Reveal(x, rv[x])).ToList();
                var res = Beacon.VerifyRollEntry(commits, reveals, live, state.TurnIndex, prevBeacon);
                if (!res.Ok) break;
                var r = Engine.Apply(state, new GameAction("ROLL") { Dice = res.Dice });
                if (!r.Ok) break;
                state = r.State!; prevBeacon = res.Beacon!; rollsApplied++;
            }
        }

        foreach (var hex in logHex)
        {
            JsonElement f;
            try { using var d = JsonDocument.Parse(Encoding.UTF8.GetString(Tx.FromHex(hex))); f = d.RootElement.Clone(); }
            catch { continue; }
            if (f.ValueKind != JsonValueKind.Object || !f.TryGetProperty("kind", out var kE)) continue;
            string kind = kE.GetString() ?? "";
            if (kind is "manifest" or "announce" or "chat") continue;       // do not affect game state
            if (!f.TryGetProperty("signPub", out var spE) || !f.TryGetProperty("sig", out var sgE)) continue;
            string signPub = spE.GetString() ?? "";
            byte[] sig; try { sig = Tx.FromHex(sgE.GetString()!); } catch { continue; }
            if (!TableMsg.VerifyFrame(f, signPub, sig)) continue;            // AUTHENTICATE every frame

            switch (kind)
            {
                case "table":
                    if (maxSeats == null) { maxSeats = f.GetProperty("maxSeats").GetInt32(); host = signPub; }
                    break;
                case "seat":
                {
                    int seat = f.GetProperty("seat").GetInt32();
                    string who = f.GetProperty("who").GetString()!;
                    if (!started && !seats.ContainsKey(seat) && who == signPub && !seatKeys.Values.Contains(signPub))
                    { seats[seat] = who; seatKeys[seat] = signPub; }
                    break;
                }
                case "start":
                {
                    if (!started && signPub == host)
                    {
                        var cur = string.Join(",", seats.OrderBy(s => s.Key).Select(s => $"{s.Key}:{s.Value}"));
                        var claimed = string.Join(",", f.GetProperty("seatMap").EnumerateArray()
                            .Select(e => (seat: e.GetProperty("seat").GetInt32(), who: e.GetProperty("who").GetString()!))
                            .OrderBy(x => x.seat).Select(x => $"{x.seat}:{x.who}"));
                        if (cur == claimed)
                        {
                            var cfg = f.GetProperty("config");
                            try { state = Engine.InitialState(cfg.GetProperty("network").GetString()!, cfg.GetProperty("seatCount").GetInt32(), cfg.GetProperty("bankReserve").GetInt64()); started = true; TryRoll(); }
                            catch { state = null; started = false; }
                        }
                    }
                    break;
                }
                case "commit":
                {
                    int seat = f.GetProperty("seat").GetInt32(); long roll = f.GetProperty("roll").GetInt64();
                    if (seatKeys.GetValueOrDefault(seat) == signPub)
                    {
                        if (!commitsBySeq.TryGetValue(roll, out var map)) { map = new(); commitsBySeq[roll] = map; }
                        if (!map.ContainsKey(seat)) map[seat] = Tx.FromHex(f.GetProperty("c").GetString()!);
                    }
                    break;
                }
                case "reveal":
                {
                    int seat = f.GetProperty("seat").GetInt32(); long roll = f.GetProperty("roll").GetInt64();
                    if (seatKeys.GetValueOrDefault(seat) == signPub)
                    {
                        if (!revealsBySeq.TryGetValue(roll, out var map)) { map = new(); revealsBySeq[roll] = map; }
                        if (!map.ContainsKey(seat)) map[seat] = Tx.FromHex(f.GetProperty("s").GetString()!);
                    }
                    TryRoll();
                    break;
                }
                case "action":
                {
                    if (started && state != null)
                    {
                        var action = StateJson.ParseAction(f.GetProperty("action"));
                        if (action.Type == "ROLL") break;                   // raw dice never accepted
                        int owner = action.Type == "LEAVE" ? action.SeatIndex : state.Current;
                        if (seatKeys.GetValueOrDefault(owner) == signPub)
                        {
                            try { var r = Engine.Apply(state, action); if (r.Ok) { state = r.State!; TryRoll(); } } catch { }
                        }
                    }
                    break;
                }
            }
        }
        return state == null ? null : Canonical.HashState(state);
    }
}
