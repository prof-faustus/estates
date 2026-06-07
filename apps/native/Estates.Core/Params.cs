// Estates.Core/Params.cs — the single source of truth for board + rules data.
//
// Loads the EXACT params/estates.v1.json (embedded as a resource), so the rules DATA
// cannot diverge from the single source of truth. The derived rent/cost FORMULAS are
// implemented here. Note: half-up rounding (toward +Inf); C# Math.Round is
// banker's rounding by default, so every rounding uses JsRound = floor(x + 0.5).
using System.Reflection;
using System.Text.Json;

namespace Estates.Core;

public sealed record BoardSpace(
    int Id, string Name, string Type,
    string? Group, long? BasePrice, string? Corner, string? Deck, string? Tax);

public sealed record CardEffect(
    string Kind, int Space, bool CollectIfPass, string Category,
    int Delta, long Amount, long PerHouse, long PerEstate);

public sealed record Card(string Id, string Text, CardEffect Effect);

public sealed record GroupDef(long BuildCost, IReadOnlyList<int> MemberPropertyIds);

public sealed class Params
{
    public required string ParamsVersion { get; init; }
    public required long StartingBalancePerSeat { get; init; }
    public required long Salary { get; init; }
    public required int MaxSeats { get; init; }
    public required int MinSeats { get; init; }
    public required int BoardSize { get; init; }

    // rent_factors
    public required double RentBaseFactor { get; init; }
    public required double FullGroupUnbuiltMultiplier { get; init; }
    public required IReadOnlyList<double> BuildMultipliers { get; init; }
    public required double EstateMultiplier { get; init; }
    public required long StationBase { get; init; }
    public required IReadOnlyList<long> UtilityFactor { get; init; }
    public required double MortgageValueFactor { get; init; }
    public required double UnmortgageCostFactor { get; init; }
    public required double SellBuildingRefundFactor { get; init; }

    public required long Houses { get; init; }
    public required long Estates { get; init; }

    public required IReadOnlyList<BoardSpace> Board { get; init; }
    public required IReadOnlyDictionary<string, GroupDef> Groups { get; init; }
    public required IReadOnlyDictionary<string, (int SpaceId, long Flat, double PercentOfWorth)> Taxes { get; init; }
    public required IReadOnlyDictionary<string, IReadOnlyList<Card>> Decks { get; init; }

    // holding_yard
    public required int HoldingSpaceId { get; init; }
    public required long PayToLeave { get; init; }
    public required int MaxDoubleAttempts { get; init; }
    public required int DoublesToHolding { get; init; }

    /// <summary>JS Math.round: round half toward +Infinity.</summary>
    public static long JsRound(double x) => (long)Math.Floor(x + 0.5);

    public long BaseRent(long basePrice) => JsRound(basePrice * RentBaseFactor);

    public long PropertyRent(long basePrice, int level, bool fullGroup)
    {
        long b = BaseRent(basePrice);
        if (level <= 0) return fullGroup ? b * (long)FullGroupUnbuiltMultiplier : b;
        if (level >= 5) return JsRound(b * EstateMultiplier);
        return JsRound(b * BuildMultipliers[level - 1]);
    }

    public long StationRent(int stationsOwned)
        => stationsOwned <= 0 ? 0 : StationBase * (long)Math.Pow(2, stationsOwned - 1);

    public long UtilityRent(int diceTotal, int utilitiesOwned)
        => utilitiesOwned <= 0 ? 0 : diceTotal * UtilityFactor[Math.Min(utilitiesOwned, 2) - 1];

    public long MortgageValue(long basePrice) => JsRound(basePrice * MortgageValueFactor);

    public long UnmortgageCost(long basePrice) => JsRound(MortgageValue(basePrice) * UnmortgageCostFactor);

    public long BuildCost(string group) => Groups.TryGetValue(group, out var g) ? g.BuildCost : 0;

    // ---- load the embedded estates.v1.json ---------------------------------
    private static readonly Lazy<Params> _instance = new(Load);
    public static Params Instance => _instance.Value;

    private static Params Load()
    {
        var asm = Assembly.GetExecutingAssembly();
        var name = asm.GetManifestResourceNames().Single(n => n.EndsWith("estates.v1.json", StringComparison.Ordinal));
        using var stream = asm.GetManifestResourceStream(name)!;
        using var doc = JsonDocument.Parse(stream);
        var r = doc.RootElement;

        var scalars = r.GetProperty("scalars");
        var rf = r.GetProperty("rent_factors");
        var supply = r.GetProperty("build_supply");
        var hy = r.GetProperty("holding_yard");

        var board = new List<BoardSpace>();
        foreach (var s in r.GetProperty("board").EnumerateArray())
        {
            board.Add(new BoardSpace(
                s.GetProperty("id").GetInt32(),
                s.GetProperty("name").GetString()!,
                s.GetProperty("type").GetString()!,
                s.TryGetProperty("group", out var g) ? g.GetString() : null,
                s.TryGetProperty("base_price", out var bp) ? bp.GetInt64() : null,
                s.TryGetProperty("corner", out var c) ? c.GetString() : null,
                s.TryGetProperty("deck", out var d) ? d.GetString() : null,
                s.TryGetProperty("tax", out var t) ? t.GetString() : null));
        }

        var groups = new Dictionary<string, GroupDef>();
        foreach (var gp in r.GetProperty("groups").EnumerateObject())
        {
            var members = gp.Value.GetProperty("member_property_ids").EnumerateArray().Select(x => x.GetInt32()).ToList();
            groups[gp.Name] = new GroupDef(gp.Value.GetProperty("build_cost").GetInt64(), members);
        }

        var taxes = new Dictionary<string, (int, long, double)>();
        foreach (var tx in r.GetProperty("taxes").EnumerateObject())
        {
            taxes[tx.Name] = (
                tx.Value.GetProperty("space_id").GetInt32(),
                tx.Value.GetProperty("flat").GetInt64(),
                tx.Value.TryGetProperty("percent_of_worth", out var pw) ? pw.GetDouble() : 0.0);
        }

        var decks = new Dictionary<string, IReadOnlyList<Card>>();
        foreach (var dk in r.GetProperty("decks").EnumerateObject())
        {
            var cards = new List<Card>();
            foreach (var cd in dk.Value.EnumerateArray())
            {
                var e = cd.GetProperty("effect");
                var eff = new CardEffect(
                    e.GetProperty("kind").GetString()!,
                    e.TryGetProperty("space", out var sp) ? sp.GetInt32() : 0,
                    e.TryGetProperty("collect_if_pass", out var ci) && ci.GetBoolean(),
                    e.TryGetProperty("category", out var ca) ? ca.GetString()! : "",
                    e.TryGetProperty("delta", out var de) ? de.GetInt32() : 0,
                    e.TryGetProperty("amount", out var am) ? am.GetInt64() : 0,
                    e.TryGetProperty("per_house", out var ph) ? ph.GetInt64() : 0,
                    e.TryGetProperty("per_estate", out var pe) ? pe.GetInt64() : 0);
                cards.Add(new Card(cd.GetProperty("id").GetString()!, cd.GetProperty("text").GetString()!, eff));
            }
            decks[dk.Name] = cards;
        }

        return new Params
        {
            ParamsVersion = r.GetProperty("params_version").GetString()!,
            StartingBalancePerSeat = scalars.GetProperty("starting_balance_per_seat").GetInt64(),
            Salary = scalars.GetProperty("salary").GetInt64(),
            MaxSeats = scalars.GetProperty("max_seats").GetInt32(),
            MinSeats = scalars.GetProperty("min_seats").GetInt32(),
            BoardSize = scalars.GetProperty("board_size").GetInt32(),
            RentBaseFactor = rf.GetProperty("rent_base_factor").GetDouble(),
            FullGroupUnbuiltMultiplier = rf.GetProperty("full_group_unbuilt_multiplier").GetDouble(),
            BuildMultipliers = rf.GetProperty("build_multipliers").EnumerateArray().Select(x => x.GetDouble()).ToList(),
            EstateMultiplier = rf.GetProperty("estate_multiplier").GetDouble(),
            StationBase = rf.GetProperty("station_base").GetInt64(),
            UtilityFactor = rf.GetProperty("utility_factor").EnumerateArray().Select(x => x.GetInt64()).ToList(),
            MortgageValueFactor = rf.GetProperty("mortgage_value_factor").GetDouble(),
            UnmortgageCostFactor = rf.GetProperty("unmortgage_cost_factor").GetDouble(),
            SellBuildingRefundFactor = rf.GetProperty("sell_building_refund_factor").GetDouble(),
            Houses = supply.GetProperty("houses").GetInt64(),
            Estates = supply.GetProperty("estates").GetInt64(),
            Board = board,
            Groups = groups,
            Taxes = taxes,
            Decks = decks,
            HoldingSpaceId = hy.GetProperty("space_id").GetInt32(),
            PayToLeave = hy.GetProperty("pay_to_leave").GetInt64(),
            MaxDoubleAttempts = hy.GetProperty("max_double_attempts").GetInt32(),
            DoublesToHolding = hy.GetProperty("doubles_to_holding").GetInt32(),
        };
    }
}
