// Estates.Core/Engine.cs — the native turn-FSM game engine.
//
// `Engine.Apply(state, action)` -> new state | typed rejection. Pure: no I/O, no
// clock, no own randomness (dice arrive on ROLL; deck order is injected at init).
// Ported line-for-line from packages/engine/src/index.ts and proven byte-exact
// against the same conformance vectors (see Estates.Conformance). The immutable
// TS spreads are reproduced by deep-cloning the input once and threading mutations
// through a single working copy — identical final state, by construction.
using System.Globalization;

namespace Estates.Core;

public sealed class Seat
{
    public int Id;
    public long Balance;
    public int Position;
    public bool InHolding;
    public int HoldingTurns;
    public int ReprieveCards;
    public bool Bankrupt;
    public Seat Clone() => (Seat)MemberwiseClone();
}

public sealed class Title
{
    public int? Owner;       // seat index, or null = bank
    public int BuildLevel;   // 0..5
    public bool Mortgaged;
    public Title Clone() => (Title)MemberwiseClone();
}

public sealed class GameState
{
    public string Network = "regtest";
    public List<Seat> Seats = new();
    public Dictionary<int, Title> Titles = new();
    public long BankReserve;
    public long HousesRemaining;
    public long EstatesRemaining;
    public int Current;
    public string Phase = "AWAIT_ROLL";
    public int TurnIndex;
    public bool DoublesPending;
    public int DoublesCount;
    public Dictionary<string, int> DeckCursor = new();
    public Dictionary<string, List<int>>? DeckOrder;
    public int[]? LastRoll;          // [d1,d2] or null
    public int? PendingTitle;
    public int? Winner;
    public List<string> Log = new();

    public GameState DeepClone()
    {
        var g = new GameState
        {
            Network = Network,
            Seats = Seats.Select(s => s.Clone()).ToList(),
            Titles = Titles.ToDictionary(kv => kv.Key, kv => kv.Value.Clone()),
            BankReserve = BankReserve,
            HousesRemaining = HousesRemaining,
            EstatesRemaining = EstatesRemaining,
            Current = Current,
            Phase = Phase,
            TurnIndex = TurnIndex,
            DoublesPending = DoublesPending,
            DoublesCount = DoublesCount,
            DeckCursor = new Dictionary<string, int>(DeckCursor),
            DeckOrder = DeckOrder?.ToDictionary(kv => kv.Key, kv => new List<int>(kv.Value)),
            LastRoll = LastRoll is null ? null : new[] { LastRoll[0], LastRoll[1] },
            PendingTitle = PendingTitle,
            Winner = Winner,
            Log = new List<string>(Log),
        };
        return g;
    }
}

public sealed record Action(string Type)
{
    public int[]? Dice { get; init; }
    public string? Choice { get; init; }        // PAY_TAX: "flat" | "percent"
    public int PropertyId { get; init; }
    public int SeatIndex { get; init; }          // LEAVE; TRADE: the counterparty seat
    public long Amount { get; init; }            // TRADE: cash that changes hands
}

public sealed class ApplyResult
{
    public bool Ok { get; init; }
    public GameState? State { get; init; }
    public string? Code { get; init; }
    public string? Context { get; init; }
    public static ApplyResult Reject(string code, string ctx) => new() { Ok = false, Code = code, Context = ctx };
    public static ApplyResult OkState(GameState s) => new() { Ok = true, State = s };
}

public static class Engine
{
    private static readonly Params P = Params.Instance;
    private static int SIZE => P.BoardSize;
    private static BoardSpace Space(int id) => P.Board[id];
    private static bool IsTitled(BoardSpace sp) => sp.Type is "property" or "station" or "utility";
    private static Seat SeatOf(GameState s, int id) => s.Seats[id];

    public static bool IsPermutation(IReadOnlyList<int>? order, int n)
    {
        if (order is null || order.Count != n) return false;
        var seen = new bool[n];
        foreach (var v in order)
        {
            if (v < 0 || v >= n || seen[v]) return false;
            seen[v] = true;
        }
        return true;
    }

    public static GameState InitialState(string network, int seatCount, long bankReserve,
        Dictionary<string, List<int>>? deckOrder = null, bool requireFairDecks = false)
    {
        if (requireFairDecks)
        {
            foreach (var deck in P.Decks.Keys)
                if (!IsPermutation(deckOrder?.GetValueOrDefault(deck), P.Decks[deck].Count))
                    throw new InvalidOperationException($"live game requires a fair committed deckOrder for {deck}");
        }
        var seats = new List<Seat>();
        for (int i = 0; i < seatCount; i++)
            seats.Add(new Seat { Id = i, Balance = P.StartingBalancePerSeat, Position = 0 });
        var titles = new Dictionary<int, Title>();
        foreach (var sp in P.Board)
            if (IsTitled(sp)) titles[sp.Id] = new Title { Owner = null, BuildLevel = 0, Mortgaged = false };
        return new GameState
        {
            Network = network, Seats = seats, Titles = titles,
            BankReserve = bankReserve, HousesRemaining = P.Houses, EstatesRemaining = P.Estates,
            Current = 0, Phase = "AWAIT_ROLL", TurnIndex = 0,
            DoublesPending = false, DoublesCount = 0,
            DeckCursor = new Dictionary<string, int> { ["Fate"] = 0, ["Treasury"] = 0 },
            DeckOrder = deckOrder,
            LastRoll = null, PendingTitle = null, Winner = null, Log = new List<string>(),
        };
    }

    public static List<string> LegalActions(GameState s) => s.Phase switch
    {
        "AWAIT_ROLL" => new() { "ROLL", "FORFEIT" },
        "AWAIT_BUY" => new() { "BUY", "DECLINE" },
        "AWAIT_TAX" => new() { "PAY_TAX" },
        "AWAIT_POST" => new() { "BUILD", "SELL_BUILD", "MORTGAGE", "UNMORTGAGE", "END_TURN" },
        _ => new(),
    };

    // ---- helpers (mutate the working copy) ---------------------------------
    private static void Note(GameState s, string line) => s.Log.Add(line);

    private static IReadOnlyList<int> MembersOf(string group)
        => P.Groups.TryGetValue(group, out var g) ? g.MemberPropertyIds : Array.Empty<int>();

    private static bool OwnsFullGroup(GameState s, int seatId, string group)
    {
        var m = MembersOf(group);
        return m.Count > 0 && m.All(id => s.Titles.TryGetValue(id, out var t) && t.Owner == seatId);
    }

    private static int CountCategoryOwned(GameState s, int seatId, string type)
    {
        int n = 0;
        foreach (var sp in P.Board)
            if (sp.Type == type && s.Titles.TryGetValue(sp.Id, out var t) && t.Owner == seatId) n++;
        return n;
    }

    public static long NetWorth(GameState s, int seatId)
    {
        long w = SeatOf(s, seatId).Balance;
        foreach (var sp in P.Board)
        {
            if (!IsTitled(sp)) continue;
            var t = s.Titles[sp.Id];
            if (t.Owner != seatId) continue;
            w += P.MortgageValue(sp.BasePrice ?? 0);
            if (!t.Mortgaged && t.BuildLevel > 0 && sp.Group != null)
                w += t.BuildLevel * P.BuildCost(sp.Group);
        }
        return w;
    }

    private static void BankToSeat(GameState s, int seatId, long amount)
    {
        long pay = Math.Min(amount, s.BankReserve);
        s.BankReserve -= pay;
        SeatOf(s, seatId).Balance += pay;
    }

    private static void RaiseFunds(GameState s, int seatId, long target)
    {
        while (SeatOf(s, seatId).Balance < target)
        {
            int best = -1, bestLevel = 0;
            foreach (var sp in P.Board)
            {
                if (sp.Group == null) continue;
                if (s.Titles.TryGetValue(sp.Id, out var t) && t.Owner == seatId && t.BuildLevel > bestLevel)
                { best = sp.Id; bestLevel = t.BuildLevel; }
            }
            if (best < 0) break;
            SellBuildInternal(s, seatId, best);
        }
        foreach (var sp in P.Board)
        {
            if (SeatOf(s, seatId).Balance >= target) break;
            if (!IsTitled(sp)) continue;
            var t = s.Titles[sp.Id];
            if (t.Owner == seatId && !t.Mortgaged && t.BuildLevel == 0)
            {
                long v = P.MortgageValue(sp.BasePrice ?? 0);
                t.Mortgaged = true;
                BankToSeat(s, seatId, v);
            }
        }
    }

    private static void SellBuildInternal(GameState s, int seatId, int id)
    {
        var sp = Space(id); var t = s.Titles[id];
        if (sp.Group == null || t.BuildLevel <= 0) return;
        long refund = Params.JsRound(P.BuildCost(sp.Group) * P.SellBuildingRefundFactor);
        if (t.BuildLevel == 5) { s.EstatesRemaining += 1; s.HousesRemaining -= 4; }
        else s.HousesRemaining += 1;
        t.BuildLevel -= 1;
        BankToSeat(s, seatId, refund);
    }

    private static void Charge(GameState s, int fromId, long amount, int? toId)
    {
        if (SeatOf(s, fromId).Balance < amount) RaiseFunds(s, fromId, amount);
        if (SeatOf(s, fromId).Balance >= amount)
        {
            SeatOf(s, fromId).Balance -= amount;
            if (toId is null) s.BankReserve += amount;
            else SeatOf(s, toId.Value).Balance += amount;
            return;
        }
        // bankruptcy
        long remaining = SeatOf(s, fromId).Balance;
        SeatOf(s, fromId).Balance = 0; SeatOf(s, fromId).Bankrupt = true;
        if (toId is null) s.BankReserve += remaining;
        else SeatOf(s, toId.Value).Balance += remaining;
        foreach (var sp in P.Board)
        {
            if (!IsTitled(sp)) continue;
            var t = s.Titles[sp.Id];
            if (t.Owner != fromId) continue;
            if (t.BuildLevel == 5) { s.EstatesRemaining += 1; s.HousesRemaining -= 4; }
            else if (t.BuildLevel > 0) s.HousesRemaining += t.BuildLevel;
            t.Owner = toId; t.BuildLevel = 0;
        }
        if (toId is not null)
            SeatOf(s, toId.Value).ReprieveCards += SeatOf(s, fromId).ReprieveCards;
        SeatOf(s, fromId).ReprieveCards = 0;
        Note(s, $"seat {fromId} bankrupt; assets to {(toId is null ? "bank" : $"seat {toId}")}");
    }

    private static List<int> SolventSeats(GameState s) => s.Seats.Where(x => !x.Bankrupt).Select(x => x.Id).ToList();

    private static void MaybeGameOver(GameState s)
    {
        var alive = SolventSeats(s);
        if (alive.Count <= 1) { s.Phase = "GAME_OVER"; s.Winner = alive.Count == 1 ? alive[0] : (int?)null; }
    }

    private static long ComputeRent(GameState s, int id, int diceTotal)
    {
        var sp = Space(id); var t = s.Titles[id];
        if (t.Owner is null || t.Mortgaged) return 0;
        if (sp.Type == "station") return P.StationRent(CountCategoryOwned(s, t.Owner.Value, "station"));
        if (sp.Type == "utility") return P.UtilityRent(diceTotal, CountCategoryOwned(s, t.Owner.Value, "utility"));
        bool full = sp.Group != null && OwnsFullGroup(s, t.Owner.Value, sp.Group);
        return P.PropertyRent(sp.BasePrice ?? 0, t.BuildLevel, full);
    }

    private static void GoToHolding(GameState s)
    {
        int id = SeatOf(s, s.Current).Id;
        var seat = SeatOf(s, id);
        seat.Position = P.HoldingSpaceId; seat.InHolding = true; seat.HoldingTurns = 0;
        s.DoublesPending = false; s.DoublesCount = 0;
        Note(s, $"seat {id} sent to the Holding Yard");
    }

    private static void ResolveLanding(GameState s, int diceTotal)
    {
        int id = s.Current;
        int pos = SeatOf(s, id).Position;
        var sp = Space(pos);

        if (sp.Type == "corner")
        {
            if (sp.Corner == "summons") { GoToHolding(s); s.Phase = "AWAIT_POST"; return; }
            s.Phase = "AWAIT_POST"; return;
        }
        if (sp.Type == "tax")
        {
            if (sp.Tax == "income_levy") { s.Phase = "AWAIT_TAX"; return; }
            long flat = P.Taxes["luxury_duty"].Flat;
            Charge(s, id, flat, null); Note(s, $"seat {id} pays Luxury Duty {flat}"); s.Phase = "AWAIT_POST"; return;
        }
        if (sp.Type == "card") { ResolveCard(s, sp.Deck!, diceTotal); return; }
        if (IsTitled(sp))
        {
            var t = s.Titles[pos];
            if (t.Owner is null) { s.Phase = "AWAIT_BUY"; s.PendingTitle = pos; return; }
            if (t.Owner == id || t.Mortgaged) { s.Phase = "AWAIT_POST"; return; }
            long rent = ComputeRent(s, pos, diceTotal);
            Charge(s, id, rent, t.Owner); Note(s, $"seat {id} pays rent {rent} to seat {t.Owner}"); s.Phase = "AWAIT_POST"; return;
        }
        s.Phase = "AWAIT_POST";
    }

    private static int Nearest(int pos, string type)
    {
        for (int d = 1; d <= SIZE; d++)
        {
            int id = (pos + d) % SIZE;
            if (Space(id).Type == type) return id;
        }
        return pos;
    }

    private static IReadOnlyList<int> DrawOrder(GameState s, string deck, int n)
    {
        var inj = s.DeckOrder?.GetValueOrDefault(deck);
        if (IsPermutation(inj, n)) return inj!;
        return Enumerable.Range(0, n).ToList();
    }

    private static void ResolveCard(GameState s, string deck, int diceTotal)
    {
        var cards = P.Decks[deck];
        var order = DrawOrder(s, deck, cards.Count);
        int cursor = s.DeckCursor.GetValueOrDefault(deck);
        int cardIdx = order[cursor % order.Count];
        var card = cards[cardIdx];
        s.DeckCursor[deck] = (cursor + 1) % order.Count;
        Note(s, $"seat {s.Current} draws {deck}: {card.Text}");
        ApplyCardEffect(s, card.Effect, diceTotal);
    }

    private static void ApplyCardEffect(GameState s, CardEffect e, int diceTotal)
    {
        int id = s.Current;
        switch (e.Kind)
        {
            case "COLLECT_BANK": BankToSeat(s, id, e.Amount); s.Phase = "AWAIT_POST"; return;
            case "PAY_BANK": Charge(s, id, e.Amount, null); s.Phase = "AWAIT_POST"; return;
            case "COLLECT_EACH":
                foreach (var o in SolventSeats(s)) if (o != id) Charge(s, o, e.Amount, id);
                s.Phase = "AWAIT_POST"; return;
            case "PAY_EACH":
                foreach (var o in SolventSeats(s)) if (o != id) Charge(s, id, e.Amount, o);
                s.Phase = "AWAIT_POST"; return;
            case "REPAIRS":
            {
                long houses = 0, estates = 0;
                foreach (var sp in P.Board)
                {
                    if (s.Titles.TryGetValue(sp.Id, out var t) && t.Owner == id)
                    { if (t.BuildLevel == 5) estates++; else houses += t.BuildLevel; }
                }
                Charge(s, id, houses * e.PerHouse + estates * e.PerEstate, null); s.Phase = "AWAIT_POST"; return;
            }
            case "REPRIEVE_GRANT": SeatOf(s, id).ReprieveCards += 1; s.Phase = "AWAIT_POST"; return;
            case "GOTO_HOLDING": GoToHolding(s); s.Phase = "AWAIT_POST"; return;
            case "MOVE_RELATIVE":
            {
                int np = ((SeatOf(s, id).Position + e.Delta) % SIZE + SIZE) % SIZE;
                SeatOf(s, id).Position = np; ResolveLanding(s, diceTotal); return;
            }
            case "MOVE_TO":
            {
                int from = SeatOf(s, id).Position;
                if (e.CollectIfPass && e.Space <= from) BankToSeat(s, id, P.Salary);
                SeatOf(s, id).Position = e.Space; ResolveLanding(s, diceTotal); return;
            }
            case "MOVE_TO_NEAREST":
            {
                int target = Nearest(SeatOf(s, id).Position, e.Category);
                if (e.CollectIfPass && target <= SeatOf(s, id).Position) BankToSeat(s, id, P.Salary);
                SeatOf(s, id).Position = target; ResolveLanding(s, diceTotal); return;
            }
        }
    }

    // ---- apply --------------------------------------------------------------
    public static ApplyResult Apply(GameState input, Action a)
    {
        var s = input.DeepClone();
        if (s.Phase == "GAME_OVER") return ApplyResult.Reject("GAME_OVER", "game is over");
        if (a.Type == "LEAVE") return DoLeave(s, a.SeatIndex);
        return a.Type switch
        {
            "ROLL" => DoRoll(s, a.Dice!),
            "BUY" => DoBuy(s),
            "DECLINE" => DoDecline(s),
            "PAY_TAX" => DoTax(s, a.Choice!),
            "BUILD" => DoBuild(s, a.PropertyId),
            "SELL_BUILD" => DoSellBuild(s, a.PropertyId),
            "MORTGAGE" => DoMortgage(s, a.PropertyId),
            "UNMORTGAGE" => DoUnmortgage(s, a.PropertyId),
            "TRADE" => DoTrade(s, a.PropertyId, a.SeatIndex, a.Amount, a.Choice),
            "USE_REPRIEVE" => DoUseReprieve(s),
            "FORFEIT" => DoForfeit(s),
            "END_TURN" => DoEndTurn(s),
            _ => ApplyResult.Reject("WRONG_PHASE", $"unknown action {a.Type}"),
        };
    }

    private static ApplyResult DoLeave(GameState s, int seatId)
    {
        if (seatId < 0 || seatId >= s.Seats.Count) return ApplyResult.OkState(s);
        var leaver = s.Seats[seatId];
        if (leaver.Bankrupt) return ApplyResult.OkState(s);
        var others = SolventSeats(s).Where(id => id != seatId).ToList();
        if (others.Count > 0)
        {
            int winner = others[0];
            foreach (var id in others) if (NetWorth(s, id) > NetWorth(s, winner)) winner = id;
            SeatOf(s, winner).Balance += leaver.Balance;
            SeatOf(s, winner).ReprieveCards += leaver.ReprieveCards;
            foreach (var sp in P.Board)
                if (IsTitled(sp) && s.Titles[sp.Id].Owner == seatId) s.Titles[sp.Id].Owner = winner;
            leaver.Balance = 0; leaver.Bankrupt = true; leaver.ReprieveCards = 0;
            Note(s, $"seat {seatId} leaves; money + assets default to the leading player (seat {winner})");
        }
        else
        {
            leaver.Balance = 0; leaver.Bankrupt = true; leaver.ReprieveCards = 0;
            Note(s, $"seat {seatId} leaves the table");
        }
        if (s.Current == seatId)
        {
            int next = s.Current;
            for (int i = 1; i <= s.Seats.Count; i++)
            {
                int cand = (s.Current + i) % s.Seats.Count;
                if (!SeatOf(s, cand).Bankrupt) { next = cand; break; }
            }
            s.Current = next; s.Phase = "AWAIT_ROLL"; s.DoublesPending = false; s.DoublesCount = 0; s.TurnIndex += 1;
        }
        MaybeGameOver(s);
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoForfeit(GameState s)
    {
        if (s.Phase != "AWAIT_ROLL") return ApplyResult.Reject("WRONG_PHASE", $"cannot FORFEIT in {s.Phase}");
        s.Phase = "AWAIT_POST"; s.DoublesPending = false; s.DoublesCount = 0;
        Note(s, $"seat {s.Current} forfeits the turn");
        EndTurnTransition(s);
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoRoll(GameState s, int[] dice)
    {
        if (s.Phase != "AWAIT_ROLL") return ApplyResult.Reject("WRONG_PHASE", $"cannot ROLL in {s.Phase}");
        if (dice.Length != 2 || dice.Any(d => d < 1 || d > 6))
            return ApplyResult.Reject("INVALID_DICE", $"dice {string.Join(",", dice)}");
        int id = s.Current;
        int d1 = dice[0], d2 = dice[1];
        int total = d1 + d2;
        bool isDouble = d1 == d2;
        s.LastRoll = new[] { d1, d2 };
        var sc = SeatOf(s, id);

        if (sc.InHolding)
        {
            if (isDouble)
            {
                sc.InHolding = false; sc.HoldingTurns = 0;
                Note(s, $"seat {id} rolls doubles and leaves the Holding Yard");
                AdvanceAndLand(s, id, total); return ApplyResult.OkState(s);
            }
            int attempts = sc.HoldingTurns + 1;
            if (attempts >= P.MaxDoubleAttempts)
            {
                sc.HoldingTurns = 0; sc.InHolding = false;
                Charge(s, id, P.PayToLeave, null);
                Note(s, $"seat {id} pays {P.PayToLeave} to leave the Holding Yard");
                AdvanceAndLand(s, id, total); return ApplyResult.OkState(s);
            }
            sc.HoldingTurns = attempts;
            Note(s, $"seat {id} fails to roll doubles ({attempts}/{P.MaxDoubleAttempts})");
            s.Phase = "AWAIT_POST"; EndTurnTransition(s); return ApplyResult.OkState(s);
        }

        if (isDouble && s.DoublesCount + 1 >= P.DoublesToHolding)
        {
            Note(s, $"seat {id} rolls a third double");
            GoToHolding(s); s.Phase = "AWAIT_POST"; return ApplyResult.OkState(s);
        }
        s.DoublesCount = isDouble ? s.DoublesCount + 1 : 0;
        s.DoublesPending = isDouble;
        AdvanceAndLand(s, id, total);
        return ApplyResult.OkState(s);
    }

    private static void AdvanceAndLand(GameState s, int id, int total)
    {
        int from = SeatOf(s, id).Position;
        int raw = from + total;
        int np = raw % SIZE;
        if (raw >= SIZE) { BankToSeat(s, id, P.Salary); Note(s, $"seat {id} passes The Gate, collects {P.Salary}"); }
        SeatOf(s, id).Position = np;
        ResolveLanding(s, total);
    }

    private static ApplyResult DoBuy(GameState s)
    {
        if (s.Phase != "AWAIT_BUY") return ApplyResult.Reject("WRONG_PHASE", $"cannot BUY in {s.Phase}");
        int id = s.Current; int pid = s.PendingTitle!.Value;
        long price = Space(pid).BasePrice ?? 0;
        if (SeatOf(s, id).Balance < price) return ApplyResult.Reject("INSUFFICIENT_FUNDS", $"need {price} for {Space(pid).Name}");
        SeatOf(s, id).Balance -= price;
        s.BankReserve += price;
        s.Titles[pid].Owner = id;
        Note(s, $"seat {id} buys {Space(pid).Name} for {price}");
        s.Phase = "AWAIT_POST"; s.PendingTitle = null;
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoDecline(GameState s)
    {
        if (s.Phase != "AWAIT_BUY") return ApplyResult.Reject("WRONG_PHASE", $"cannot DECLINE in {s.Phase}");
        Note(s, $"seat {s.Current} declines {Space(s.PendingTitle!.Value).Name}; returns to bank unsold");
        s.Phase = "AWAIT_POST"; s.PendingTitle = null;
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoTax(GameState s, string choice)
    {
        if (s.Phase != "AWAIT_TAX") return ApplyResult.Reject("WRONG_PHASE", $"cannot PAY_TAX in {s.Phase}");
        int id = s.Current; var t = P.Taxes["income_levy"];
        long amount = choice == "flat" ? t.Flat : Params.JsRound(NetWorth(s, id) * t.PercentOfWorth);
        Charge(s, id, amount, null);
        Note(s, $"seat {id} pays Income Levy {amount} ({choice})");
        s.Phase = "AWAIT_POST";
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoBuild(GameState s, int pid)
    {
        if (s.Phase != "AWAIT_POST") return ApplyResult.Reject("WRONG_PHASE", $"cannot BUILD in {s.Phase}");
        if (pid < 0 || pid >= P.Board.Count) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var sp = P.Board[pid]; if (!IsTitled(sp)) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        if (sp.Type != "property" || sp.Group == null) return ApplyResult.Reject("NOT_TITLED_SPACE", $"{sp.Name} is not buildable");
        var t = s.Titles[pid]; int id = s.Current;
        if (t.Owner != id) return ApplyResult.Reject("NOT_OWNER", $"seat {id} does not own {sp.Name}");
        if (!OwnsFullGroup(s, id, sp.Group)) return ApplyResult.Reject("NOT_FULL_GROUP", $"{sp.Group} not fully owned");
        if (MembersOf(sp.Group).Any(m => s.Titles[m].Mortgaged)) return ApplyResult.Reject("HAS_BUILDINGS", $"{sp.Group} has a mortgaged member");
        if (t.BuildLevel >= 5) return ApplyResult.Reject("ALREADY_MAX", $"{sp.Name} at estate");
        int minLevel = MembersOf(sp.Group).Min(m => s.Titles[m].BuildLevel);
        if (t.BuildLevel > minLevel) return ApplyResult.Reject("UNEVEN_BUILD", $"must build evenly across {sp.Group}");
        int toLevel = t.BuildLevel + 1;
        if (toLevel == 5) { if (s.EstatesRemaining < 1) return ApplyResult.Reject("NO_BUILD_SUPPLY", "no estates left"); }
        else if (s.HousesRemaining < 1) return ApplyResult.Reject("NO_BUILD_SUPPLY", "no houses left");
        long cost = P.BuildCost(sp.Group);
        if (SeatOf(s, id).Balance < cost) return ApplyResult.Reject("INSUFFICIENT_FUNDS", $"need {cost} to build");
        SeatOf(s, id).Balance -= cost;
        s.BankReserve += cost;
        if (toLevel == 5) { s.EstatesRemaining -= 1; s.HousesRemaining += 4; }
        else s.HousesRemaining -= 1;
        t.BuildLevel = toLevel;
        Note(s, $"seat {id} builds {sp.Name} to level {toLevel}");
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoSellBuild(GameState s, int pid)
    {
        if (s.Phase != "AWAIT_POST") return ApplyResult.Reject("WRONG_PHASE", $"cannot SELL_BUILD in {s.Phase}");
        if (pid < 0 || pid >= P.Board.Count) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var sp = P.Board[pid]; if (sp.Group == null) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var t = s.Titles.GetValueOrDefault(pid); int id = s.Current;
        if (t == null || t.Owner != id) return ApplyResult.Reject("NOT_OWNER", $"seat {id} does not own {sp.Name}");
        if (t.BuildLevel <= 0) return ApplyResult.Reject("NOT_BUILT", $"{sp.Name} has no buildings");
        int maxLevel = MembersOf(sp.Group).Max(m => s.Titles[m].BuildLevel);
        if (t.BuildLevel < maxLevel) return ApplyResult.Reject("UNEVEN_BUILD", $"must sell evenly across {sp.Group}");
        SellBuildInternal(s, id, pid);
        Note(s, $"seat {id} sells a building on {sp.Name}");
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoMortgage(GameState s, int pid)
    {
        if (s.Phase != "AWAIT_POST") return ApplyResult.Reject("WRONG_PHASE", $"cannot MORTGAGE in {s.Phase}");
        if (pid < 0 || pid >= P.Board.Count) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var sp = P.Board[pid]; if (!IsTitled(sp)) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var t = s.Titles[pid]; int id = s.Current;
        if (t.Owner != id) return ApplyResult.Reject("NOT_OWNER", $"seat {id} does not own {sp.Name}");
        if (t.Mortgaged) return ApplyResult.Reject("ALREADY_MORTGAGED", $"{sp.Name}");
        if (t.BuildLevel > 0) return ApplyResult.Reject("HAS_BUILDINGS", $"sell buildings on {sp.Name} first");
        long v = P.MortgageValue(sp.BasePrice ?? 0);
        BankToSeat(s, id, v); t.Mortgaged = true;
        Note(s, $"seat {id} mortgages {sp.Name} for {v}");
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoUnmortgage(GameState s, int pid)
    {
        if (s.Phase != "AWAIT_POST") return ApplyResult.Reject("WRONG_PHASE", $"cannot UNMORTGAGE in {s.Phase}");
        if (pid < 0 || pid >= P.Board.Count) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var sp = P.Board[pid]; if (!IsTitled(sp)) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var t = s.Titles[pid]; int id = s.Current;
        if (t.Owner != id) return ApplyResult.Reject("NOT_OWNER", $"seat {id} does not own {sp.Name}");
        if (!t.Mortgaged) return ApplyResult.Reject("NOT_MORTGAGED", $"{sp.Name}");
        long cost = P.UnmortgageCost(sp.BasePrice ?? 0);
        if (SeatOf(s, id).Balance < cost) return ApplyResult.Reject("INSUFFICIENT_FUNDS", $"need {cost} to unmortgage");
        SeatOf(s, id).Balance -= cost;
        s.BankReserve += cost; t.Mortgaged = false;
        Note(s, $"seat {id} lifts mortgage on {sp.Name} for {cost}");
        return ApplyResult.OkState(s);
    }

    /// <summary>Player-to-player trade of a single undeveloped title for cash, settled atomically. choice="buy"
    /// means the current seat BUYS pid from counterparty (current pays amount); choice="sell" means the current
    /// seat SELLS pid (which it owns) to counterparty (counterparty pays amount). Either party may have a
    /// mortgaged title, but a property carrying buildings — or whose colour group carries buildings — can't be
    /// traded (sell the buildings first), exactly as the build rules require. The consenting/agreement happens
    /// at the table (UI / peer); the engine enforces ownership, solvency and the no-buildings rule.</summary>
    private static ApplyResult DoTrade(GameState s, int pid, int counterparty, long amount, string? choice)
    {
        if (s.Phase != "AWAIT_POST") return ApplyResult.Reject("WRONG_PHASE", $"cannot TRADE in {s.Phase}");
        if (pid < 0 || pid >= P.Board.Count) return ApplyResult.Reject("NO_SUCH_TITLE", $"{pid}");
        var sp = P.Board[pid]; if (!IsTitled(sp)) return ApplyResult.Reject("NOT_TITLED_SPACE", $"{sp.Name} is not a title");
        if (amount < 0) return ApplyResult.Reject("BAD_AMOUNT", "negative price");
        int me = s.Current;
        if (counterparty < 0 || counterparty >= s.Seats.Count) return ApplyResult.Reject("NO_SUCH_SEAT", $"{counterparty}");
        if (counterparty == me) return ApplyResult.Reject("SELF_TRADE", "cannot trade with yourself");
        if (SeatOf(s, counterparty).Bankrupt) return ApplyResult.Reject("SEAT_OUT", $"seat {counterparty} is out");
        var t = s.Titles[pid];
        // can't move a developed title (and not if any sibling in the group is developed)
        if (sp.Group != null && MembersOf(sp.Group).Any(m => s.Titles[m].BuildLevel > 0))
            return ApplyResult.Reject("HAS_BUILDINGS", $"sell buildings in {sp.Group} before trading");
        bool buy = (choice ?? "buy") == "buy";
        int seller = buy ? counterparty : me;
        int buyer = buy ? me : counterparty;
        if (t.Owner != seller) return ApplyResult.Reject("NOT_OWNER", $"seat {seller} does not own {sp.Name}");
        if (SeatOf(s, buyer).Balance < amount) return ApplyResult.Reject("INSUFFICIENT_FUNDS", $"seat {buyer} needs {amount}");
        SeatOf(s, buyer).Balance -= amount;
        SeatOf(s, seller).Balance += amount;
        t.Owner = buyer;
        Note(s, $"trade: seat {buyer} acquires {sp.Name} from seat {seller} for {amount}{(t.Mortgaged ? " (mortgaged)" : "")}");
        return ApplyResult.OkState(s);
    }

    /// <summary>Spend a reprieve ("get out of the Holding Yard free") card to leave holding at no cost. Valid
    /// only at the start of your turn while in the Holding Yard; you stay in AWAIT_ROLL and then roll and move
    /// normally. Additive action — it does not change ROLL's existing doubles/pay behaviour, so a player who
    /// holds reprieve cards now has a use for them.</summary>
    private static ApplyResult DoUseReprieve(GameState s)
    {
        if (s.Phase != "AWAIT_ROLL") return ApplyResult.Reject("WRONG_PHASE", $"cannot use a reprieve in {s.Phase}");
        var sc = SeatOf(s, s.Current);
        if (!sc.InHolding) return ApplyResult.Reject("NOT_HOLDING", "not in the Holding Yard");
        if (sc.ReprieveCards < 1) return ApplyResult.Reject("NO_REPRIEVE", "no reprieve cards");
        sc.ReprieveCards -= 1; sc.InHolding = false; sc.HoldingTurns = 0;
        Note(s, $"seat {s.Current} uses a reprieve card to leave the Holding Yard (free); may now roll");
        return ApplyResult.OkState(s);
    }

    private static ApplyResult DoEndTurn(GameState s)
    {
        if (s.Phase != "AWAIT_POST") return ApplyResult.Reject("WRONG_PHASE", $"cannot END_TURN in {s.Phase}");
        EndTurnTransition(s);
        return ApplyResult.OkState(s);
    }

    private static void EndTurnTransition(GameState s)
    {
        MaybeGameOver(s);
        if (s.Phase == "GAME_OVER") return;
        var cur = SeatOf(s, s.Current);
        if (s.DoublesPending && !cur.Bankrupt && !cur.InHolding)
        {
            s.Phase = "AWAIT_ROLL"; s.DoublesPending = false; return;
        }
        int next = s.Current;
        for (int i = 1; i <= s.Seats.Count; i++)
        {
            int cand = (s.Current + i) % s.Seats.Count;
            if (!SeatOf(s, cand).Bankrupt) { next = cand; break; }
        }
        s.Current = next; s.Phase = "AWAIT_ROLL"; s.DoublesPending = false; s.DoublesCount = 0; s.TurnIndex += 1;
    }
}
