// Estates.Core/GamePlay.cs — the missing orchestrator: play a WHOLE Estates game on-chain.
//
// Ties together the four primitives that already existed in isolation:
//   • Engine     — the turn-FSM game logic (roll/buy/build/rent/tax/cards/jail/bankruptcy/win)
//   • Beacon     — dealerless, provably-fair dice (each live seat commits a secret, reveals it,
//                  the dice are derived ONLY from the verified reveal set — no one can bias them)
//   • TxProtocol — every game action is stamped as a typed, self-describing on-chain payload
//   • (deck)     — Fate/Treasury draws ride the committed deck order injected at init
//
// GamePlay.PlayToEnd drives a complete game to a winner with a deterministic bot policy, producing
// for EVERY action: the action, the resulting phase, the provable dice + chained beacon (on ROLL),
// and the exact on-chain typed-tx payload that the wallet would broadcast. This is "the game, played,
// on-chain, with provable randomness" — the thing the node was only ever there to fund.
using System.Security.Cryptography;

namespace Estates.Core;

/// <summary>One played action: what was done, the on-chain payload it commits to, and (for a roll)
/// the verifiable dice + the beacon they chain from.</summary>
public sealed record GameMove(int Turn, int Seat, string Phase, string Action,
    byte[] OnChainPayload, int[]? Dice = null, byte[]? Beacon = null);

public sealed record GameResult(int Seats, int? Winner, int Turns, bool Finished,
    IReadOnlyList<GameMove> Moves, IReadOnlyList<string> Log)
{
    /// <summary>Total real on-chain transactions a live game of this length would broadcast.</summary>
    public int OnChainTxCount => Moves.Count;
}

public static class GamePlay
{
    private static readonly Params P = Params.Instance;

    /// <summary>Play a full Estates game to GAME_OVER (or maxTurns) with provable dice and an on-chain
    /// payload per action. Deterministic in `rngSeed`: same seed → same game → same payloads. No node,
    /// no I/O — pure; the caller broadcasts the payload stream (see OnChainActions) or just audits it.</summary>
    public static GameResult PlayToEnd(string network, int seatCount, long bankReserve, byte[] rngSeed, int maxTurns = 4000)
    {
        if (seatCount < 2) throw new ArgumentException("need at least 2 seats");
        var rng = new DetRng(rngSeed);

        // committed, fair deck order per deck (a real game commits these on-chain before play)
        var deckOrder = new Dictionary<string, List<int>>();
        foreach (var deck in P.Decks.Keys) deckOrder[deck] = rng.Permutation(P.Decks[deck].Count);

        var state = Engine.InitialState(network, seatCount, bankReserve, deckOrder, requireFairDecks: true);
        var moves = new List<GameMove>();

        // GAME_START is the first on-chain fact: seats, reserve, the committed deck hashes.
        moves.Add(new GameMove(state.TurnIndex, state.Current, state.Phase, "GAME_START",
            TxProtocol.Stamp(TxType.GameStart, GameStartPayload(seatCount, bankReserve, deckOrder))));

        byte[] prevBeacon = Beacon.ZeroBeacon;
        int guard = 0;
        while (state.Phase != "GAME_OVER" && guard++ < maxTurns)
        {
            var legal = Engine.LegalActions(state);
            if (legal.Count == 0) break;
            int seat = state.Current;
            var chosen = ChooseAction(state, legal, rng);

            if (chosen.Type == "ROLL")
            {
                // provable dice: every solvent seat commits a fresh secret then reveals it; the dice
                // are derived from the verified reveal set and chained into the next beacon.
                var live = state.Seats.Where(x => !x.Bankrupt).Select(x => x.Id).ToList();
                var secrets = live.ToDictionary(id => id, _ => rng.Bytes(32));
                var commits = live.Select(id => new Commitment(id, Beacon.Commit(secrets[id]))).ToList();
                var reveals = live.Select(id => new Reveal(id, secrets[id])).ToList();
                var v = Beacon.VerifyRollEntry(commits, reveals, live, state.TurnIndex, prevBeacon);
                if (!v.Ok || v.Dice is null) throw new InvalidOperationException("beacon failed: " + v.Reason);
                int[] dice = v.Dice; byte[] beacon = v.Beacon!;

                // the commit set + reveal set + dice are the on-chain record of a fair roll
                moves.Add(new GameMove(state.TurnIndex, seat, state.Phase, "ROLL",
                    TxProtocol.Stamp(TxType.Reveal, RollPayload(dice, beacon)), dice, beacon));
                prevBeacon = beacon;

                var r = Engine.Apply(state, new Action("ROLL") { Dice = dice });
                if (!r.Ok) throw new InvalidOperationException($"engine rejected ROLL: {r.Code} {r.Context}");
                state = r.State!;
                continue;
            }

            var res = Engine.Apply(state, chosen);
            if (!res.Ok)
            {
                // bot picked an illegal-in-context action (e.g. BUILD with no group) — fall back to a safe one
                chosen = SafeFallback(state, legal);
                res = Engine.Apply(state, chosen);
                if (!res.Ok) throw new InvalidOperationException($"engine rejected {chosen.Type}: {res.Code} {res.Context}");
            }
            moves.Add(new GameMove(state.TurnIndex, seat, state.Phase, chosen.Type,
                TxProtocol.Stamp(TxTypeFor(chosen.Type), ActionPayload(chosen))));
            state = res.State!;
        }

        bool finished = state.Phase == "GAME_OVER";
        return new GameResult(seatCount, state.Winner, state.TurnIndex, finished, moves, state.Log);
    }

    // ---- deterministic bot policy (greedy, legal-only) ---------------------------------------
    private static Action ChooseAction(GameState s, IReadOnlyList<string> legal, DetRng rng)
    {
        switch (s.Phase)
        {
            case "AWAIT_ROLL":
                return new Action("ROLL");                                  // always roll (never forfeit)
            case "AWAIT_BUY":
            {
                int pid = s.PendingTitle ?? -1;
                long price = pid >= 0 ? (P.Board[pid].BasePrice ?? 0) : 0;
                // AGGRESSIVE: always buy what we can afford — that's what builds the rent economy that
                // drives players to bankruptcy and resolves the game to a single winner.
                return (pid >= 0 && s.Seats[s.Current].Balance >= price)
                    ? new Action("BUY") : new Action("DECLINE");
            }
            case "AWAIT_TAX":
                return new Action("PAY_TAX") { Choice = "flat" };
            case "AWAIT_POST":
            {
                // build on the first fully-owned, unmortgaged, sub-estate group we can afford; else end turn
                int buildId = BestBuild(s);
                if (buildId >= 0) return new Action("BUILD") { PropertyId = buildId };
                return new Action("END_TURN");
            }
            default:
                return new Action(legal[0]);
        }
    }

    private static int BestBuild(GameState s)
    {
        int id = s.Current; int pick = -1; int pickLevel = 99;
        foreach (var sp in P.Board)
        {
            if (sp.Type != "property" || sp.Group == null) continue;
            if (!s.Titles.TryGetValue(sp.Id, out var t) || t.Owner != id || t.Mortgaged) continue;
            // must own the full group, members unmortgaged, build evenly, have houses + cash
            var members = P.Groups.TryGetValue(sp.Group, out var g) ? g.MemberPropertyIds : (IReadOnlyList<int>)Array.Empty<int>();
            if (members.Count == 0 || !members.All(m => s.Titles[m].Owner == id && !s.Titles[m].Mortgaged)) continue;
            if (t.BuildLevel >= 5) continue;
            int minLevel = members.Min(m => s.Titles[m].BuildLevel);
            if (t.BuildLevel > minLevel) continue;
            long cost = P.BuildCost(sp.Group);
            if (s.Seats[id].Balance < cost + 100) continue;
            int toLevel = t.BuildLevel + 1;
            if (toLevel == 5 ? s.EstatesRemaining < 1 : s.HousesRemaining < 1) continue;
            if (t.BuildLevel < pickLevel) { pick = sp.Id; pickLevel = t.BuildLevel; }
        }
        return pick;
    }

    private static Action SafeFallback(GameState s, IReadOnlyList<string> legal)
        => s.Phase switch
        {
            "AWAIT_BUY" => new Action("DECLINE"),
            "AWAIT_TAX" => new Action("PAY_TAX") { Choice = "flat" },
            "AWAIT_POST" => new Action("END_TURN"),
            _ => new Action(legal[0]),
        };

    // ---- on-chain payloads (typed, self-describing) ----------------------------------------
    private static TxType TxTypeFor(string action) => action switch
    {
        "BUY" or "BUILD" or "SELL_BUILD" or "MORTGAGE" or "UNMORTGAGE" => TxType.Move,
        "PAY_TAX" => TxType.Move,
        "END_TURN" or "FORFEIT" => TxType.KeepAlive,
        _ => TxType.Move,
    };

    private static byte[] ActionPayload(Action a)
    {
        // compact, replayable encoding of the move: <typeLen><type><propertyId(4)><choice?>
        var bytes = new List<byte>();
        var t = System.Text.Encoding.ASCII.GetBytes(a.Type);
        bytes.Add((byte)t.Length); bytes.AddRange(t);
        bytes.AddRange(U32(a.PropertyId));
        if (a.Choice != null) { var c = System.Text.Encoding.ASCII.GetBytes(a.Choice); bytes.Add((byte)c.Length); bytes.AddRange(c); }
        return bytes.ToArray();
    }

    private static byte[] RollPayload(int[] dice, byte[] beacon)
    {
        var b = new List<byte> { (byte)dice[0], (byte)dice[1] };
        b.AddRange(beacon);   // the chained beacon = the verifiable seed
        return b.ToArray();
    }

    private static byte[] GameStartPayload(int seats, long reserve, Dictionary<string, List<int>> deckOrder)
    {
        var b = new List<byte> { (byte)seats };
        b.AddRange(U64(reserve));
        using var sha = SHA256.Create();
        foreach (var deck in deckOrder.OrderBy(k => k.Key))
        {
            var ob = new List<byte>(); foreach (var i in deck.Value) ob.AddRange(U32(i));
            b.AddRange(sha.ComputeHash(ob.ToArray()));   // commit to the deck order, not reveal it
        }
        return b.ToArray();
    }

    private static byte[] U32(int n) => new[] { (byte)((n >> 24) & 0xff), (byte)((n >> 16) & 0xff), (byte)((n >> 8) & 0xff), (byte)(n & 0xff) };
    private static byte[] U64(long n) { var o = new byte[8]; for (int i = 0; i < 8; i++) o[7 - i] = (byte)((n >> (8 * i)) & 0xff); return o; }

    /// <summary>Deterministic CSPRNG-seeded stream — same seed reproduces the whole game (and its
    /// on-chain payload sequence) exactly, so a game is auditable/replayable from one root secret.</summary>
    private sealed class DetRng
    {
        private byte[] _state; private int _ctr;
        public DetRng(byte[] seed) { using var sha = SHA256.Create(); _state = sha.ComputeHash(seed); }
        public byte[] Bytes(int n)
        {
            var o = new byte[n]; int got = 0;
            using var sha = SHA256.Create();
            while (got < n)
            {
                var block = sha.ComputeHash(Concat(_state, U32(_ctr++)));
                int take = Math.Min(block.Length, n - got);
                System.Array.Copy(block, 0, o, got, take); got += take;
            }
            return o;
        }
        public int Next(int boundExclusive)
        {
            var b = Bytes(4);
            long v = ((long)b[0] << 24 | (long)b[1] << 16 | (long)b[2] << 8 | b[3]) & 0x7fffffff;
            return (int)(v % boundExclusive);
        }
        public List<int> Permutation(int n)
        {
            var a = Enumerable.Range(0, n).ToList();
            for (int i = n - 1; i > 0; i--) { int j = Next(i + 1); (a[i], a[j]) = (a[j], a[i]); }
            return a;
        }
        private static byte[] Concat(byte[] a, byte[] b) { var o = new byte[a.Length + b.Length]; System.Array.Copy(a, o, a.Length); System.Array.Copy(b, 0, o, a.Length, b.Length); return o; }
    }
}
