// Estates.Core/GameReplay.cs — the native REBUILD: replay a live game's ordered
// relay log into the SAME canonical state hash as the web NetTable. This is the
// read path of native multiplayer — it assembles the already-validated primitives
// (frame auth via TableMsg/Sign, the engine, the dice beacon, canonical hashing)
// into the deterministic state machine ported from @estates/table NetTable.rebuild.
// The dealerless DECK shuffle (dcommit/dreveal -> jointly-generated deckOrder) is
// reproduced too: when a gameId is supplied and every seat contributed entropy, the
// SAME participant-bound order the web computed is recomputed here (Deck.cs).
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GameAction = Estates.Core.Action;

namespace Estates.Core;

public static class GameReplay
{
    /// <summary>gameId = hex(sha256("estates-game:" + channel)) — the same binding the
    /// web uses (gameIdFromChannel), so a native spectator derives the identical id.</summary>
    public static string GameIdFromChannel(string channel)
        => Tx.ToHex(SHA256.HashData(Encoding.UTF8.GetBytes("estates-game:" + channel)));

    /// <summary>Replay the ordered relay log to the canonical state hash (or null).
    /// Pass the gameId (gameIdFromChannel) so the dealerless deck order is reproduced.</summary>
    public static string? ReplayStateHash(IReadOnlyList<string> logHex, string? gameId = null)
    {
        var s = ReplayState(logHex, gameId);
        return s == null ? null : Canonical.HashState(s);
    }

    /// <summary>Replay the ordered relay log (hex frames) into the live GameState, or
    /// null if the game never started. Every frame is authenticated (Ed25519 over the
    /// canonical signedBytes) and bound to its seat key, exactly like the web; raw
    /// ROLL actions are dropped (dice only from the beacon). When <paramref name="gameId"/>
    /// is given and every seat committed→revealed deck entropy, the jointly-generated
    /// deckOrder is recomputed (no single party — incl. the host — chooses it).</summary>
    public static GameState? ReplayState(IReadOnlyList<string> logHex, string? gameId = null)
    {
        int? maxSeats = null; string? host = null; bool started = false; GameState? state = null;
        bool manifestOk = false;   // the verified, seat-matching one-game key manifest was broadcast
        var seats = new Dictionary<int, string>();          // seat -> who (= signer)
        var seatKeys = new Dictionary<int, string>();        // seat -> controlling signing pub
        var deckCommits = new Dictionary<int, string>();     // seat -> deck-entropy commitment (hex)
        var deckReveals = new Dictionary<int, byte[]>();     // seat -> revealed deck entropy
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
            if (kind is "announce" or "chat") continue;                     // do not affect game state
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
                case "dcommit":
                {
                    int seat = f.GetProperty("seat").GetInt32();
                    if (!started && seatKeys.GetValueOrDefault(seat) == signPub && !deckCommits.ContainsKey(seat))
                        deckCommits[seat] = f.GetProperty("c").GetString()!;
                    break;
                }
                case "dreveal":
                {
                    int seat = f.GetProperty("seat").GetInt32();
                    if (!started && seatKeys.GetValueOrDefault(seat) == signPub && !deckReveals.ContainsKey(seat))
                        try { deckReveals[seat] = Tx.FromHex(f.GetProperty("s").GetString()!); } catch { }
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
                            // DEALERLESS DECK SHUFFLE: if a gameId is known and every seat
                            // committed→revealed entropy, recompute the SAME jointly-generated
                            // order the web did; otherwise the declared (no-shuffle) order stands.
                            Dictionary<string, List<int>>? deckOrder = null; bool requireFair = false;
                            if (gameId != null)
                            {
                                var parties = new List<SeedParty>();
                                foreach (var (seat, who) in seatKeys)
                                {
                                    if (deckCommits.TryGetValue(seat, out var c) && deckReveals.TryGetValue(seat, out var r)
                                        && Deck.CommitEntropy(r) == c)
                                        parties.Add(new SeedParty(seat, who, c, r));
                                }
                                if (parties.Count == seats.Count && parties.Count > 0)
                                {
                                    var sizes = Params.Instance.Decks.ToDictionary(kv => kv.Key, kv => kv.Value.Count);
                                    deckOrder = Deck.DealerlessDeckOrder(parties, gameId, sizes);
                                    if (deckOrder != null) requireFair = true;
                                }
                            }
                            try { state = Engine.InitialState(cfg.GetProperty("network").GetString()!, cfg.GetProperty("seatCount").GetInt32(), cfg.GetProperty("bankReserve").GetInt64(), deckOrder, requireFair); started = true; TryRoll(); }
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
                case "manifest":
                {
                    // Verify the host's one-game key manifest EXACTLY as the web rebuild does:
                    // host-signed (the frame sig was verified above), internally valid, bound to
                    // THIS game id, and its seat entries match the committed seat map. Required
                    // below for a real game (parity with the web's mandatory-manifest gate).
                    if (gameId != null && !manifestOk && signPub == host && f.TryGetProperty("m", out var mEl))
                    {
                        try
                        {
                            var km = KeyLife.Parse(mEl);
                            if (KeyLife.VerifyManifest(km).Ok && km.GameId == gameId)
                            {
                                var want = string.Join(",", seatKeys.Select(k => $"{k.Key}:{k.Value}").OrderBy(x => x, StringComparer.Ordinal));
                                var got = string.Join(",", km.Entries.Where(e => e.Purpose == "seat").Select(e => $"{e.Seat}:{e.Pub}").OrderBy(x => x, StringComparer.Ordinal));
                                if (want == got && want.Length > 0) manifestOk = true;
                            }
                        }
                        catch { }
                    }
                    break;
                }
            }
        }
        // MANDATORY one-game manifest (parity with the web rebuild): a live game bound to a
        // REAL game id MUST carry its verified, seat-matching key manifest, else it is not
        // validly live — fail closed. A null gameId (offline/local) is exempt, exactly as the
        // web exempts the zero game id.
        if (started && gameId != null && !manifestOk) return null;
        return state;
    }
}
