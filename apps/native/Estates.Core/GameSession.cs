// Estates.Core/GameSession.cs — the multiplayer engine. Two (or more) mutually-distrusting peers each run a
// GameSession and stay in lock-step with NO server and NO referee.
//
// When it's your turn you call Local(...) — it builds the move (rolling with the dealerless beacon),
// applies it to your copy, signs it, and hands you a MovePacket to send to the other peers. When a packet
// arrives from a peer you call Remote(packet) — it independently RE-DERIVES the dice from the reveals
// (it does not trust the sender's dice), checks the move is signed by the seat that's allowed to make it,
// checks the engine accepts it, and only then applies it. Because the engine is deterministic and every
// peer verifies the same way, all honest peers converge on the exact same state — and any forged, biased,
// or illegal move is rejected by every honest peer. This is the "everyone hostile, others collude" model
// as a live, incremental session (GameTranscript is the same checks applied to a whole finished game).
namespace Estates.Core;

public sealed class GameSession
{
    /// <summary>What a peer broadcasts after making a move: the action, its dice + the beacon commit/reveal
    /// set (so receivers re-derive the dice), the canonical payload, and the acting seat's signature.</summary>
    public sealed record MovePacket(string Action, int Seat, int Turn, int PropertyId, string? Choice,
        int[]? Dice, IReadOnlyList<Commitment>? Commits, IReadOnlyList<Reveal>? Reveals,
        byte[] Payload, byte[] Sig, byte[] SeatPub);

    private GameState _state;
    private byte[] _prevBeacon = Beacon.ZeroBeacon;
    private readonly SeatKey[] _keys;

    public GameState State => _state;
    public int? Winner => _state.Winner;
    public string Phase => _state.Phase;

    public GameSession(string network, int seats, long bankReserve,
        Dictionary<string, List<int>> deckOrder, SeatKey[] keys)
    {
        _state = Engine.InitialState(network, seats, bankReserve, deckOrder, requireFairDecks: true);
        _keys = keys;
    }

    /// <summary>Make the current seat's move locally and produce the packet to send to peers. For ROLL the
    /// dice come from the beacon (every live seat's secret). Throws if the action is illegal in this phase.</summary>
    public MovePacket Local(string action, int propertyId = 0, string? choice = null)
    {
        int seat = _state.Current;
        int[]? dice = null; List<Commitment>? commits = null; List<Reveal>? reveals = null; byte[] beaconUsed = _prevBeacon;
        Action a;
        if (action == "ROLL")
        {
            var live = _state.Seats.Where(s => !s.Bankrupt).Select(s => s.Id).ToList();
            reveals = live.Select(id => new Reveal(id, System.Security.Cryptography.RandomNumberGenerator.GetBytes(32))).ToList();
            commits = reveals.Select(rv => new Commitment(rv.Seat, Beacon.Commit(rv.Secret))).ToList();
            var (d, beacon) = Beacon.Roll(reveals, _state.TurnIndex, _prevBeacon);
            dice = d; a = new Action("ROLL") { Dice = dice };
        }
        else a = new Action(action) { PropertyId = propertyId, Choice = choice };

        var r = Engine.Apply(_state, a);
        if (!r.Ok) throw new InvalidOperationException($"illegal local {action}: {r.Code} {r.Context}");

        byte[] payload = Payload(action, propertyId, choice, dice, beaconUsed);
        var move = new GameMove(_state.TurnIndex, seat, _state.Phase, action, payload, dice, dice is null ? null : beaconUsed, commits, reveals);
        byte[] sig = EcdsaSign.SignPrehashDer(_keys[seat].Priv, MoveAuth.MoveDigest(move));

        if (dice is not null) _prevBeacon = Beacon.Roll(reveals!, _state.TurnIndex, beaconUsed).Beacon;
        _state = r.State!;
        return new MovePacket(action, seat, move.Turn, propertyId, choice, dice, commits, reveals, payload, sig, _keys[seat].Pub);
    }

    /// <summary>Apply a peer's move after FULL independent verification. Returns false (state unchanged) if
    /// the move is forged, the dice don't match the beacon reveals, or the engine rejects it.</summary>
    public bool Remote(MovePacket p, out string reason)
    {
        reason = "ok";
        if (p.Seat < 0 || p.Seat >= _keys.Length) { reason = "bad seat"; return false; }
        // 1) authenticity: signed by the seat that's allowed to make this move
        var move = new GameMove(p.Turn, p.Seat, _state.Phase, p.Action, p.Payload, p.Dice,
            p.Dice is null ? null : _prevBeacon, p.Commits, p.Reveals);
        if (!p.SeatPub.AsSpan().SequenceEqual(_keys[p.Seat].Pub)) { reason = "wrong seat key"; return false; }
        if (!EcdsaSign.VerifyDerPrehash(p.SeatPub, MoveAuth.MoveDigest(move), p.Sig)) { reason = "bad signature"; return false; }

        Action a;
        if (p.Action == "ROLL")
        {
            // 2) re-derive the dice from the reveals — DO NOT trust p.Dice
            var live = _state.Seats.Where(s => !s.Bankrupt).Select(s => s.Id).ToList();
            var v = Beacon.VerifyRollEntry(p.Commits ?? new List<Commitment>(), p.Reveals ?? new List<Reveal>(),
                live, _state.TurnIndex, _prevBeacon, p.Dice);
            if (!v.Ok || v.Dice is null) { reason = "beacon: " + v.Reason; return false; }
            a = new Action("ROLL") { Dice = v.Dice };
            var rr = Engine.Apply(_state, a);
            if (!rr.Ok) { reason = $"engine {rr.Code}"; return false; }
            _prevBeacon = v.Beacon!; _state = rr.State!;
            return true;
        }
        a = new Action(p.Action) { PropertyId = p.PropertyId, Choice = p.Choice };
        var r = Engine.Apply(_state, a);
        if (!r.Ok) { reason = $"engine {r.Code}"; return false; }
        _state = r.State!;
        return true;
    }

    /// <summary>Enable opt-in auctions for this session (a declined title goes to auction). Both peers call
    /// this identically at table setup so they stay in lock-step.</summary>
    public void EnableAuctions() => _state.AuctionsEnabled = true;

    /// <summary>Apply a deterministic auction BID from the seat whose turn it is to act (AuctionActor). Every
    /// peer applying the same amount lands on the identical state, so the bidding stays in lock-step exactly
    /// like a signed move.</summary>
    public bool Bid(long amount, out string reason)
    {
        reason = "ok";
        var r = Engine.Apply(_state, new Action("BID") { Amount = amount });
        if (!r.Ok) { reason = $"{r.Code} {r.Context}"; return false; }
        _state = r.State!; return true;
    }

    /// <summary>Apply a deterministic auction PASS from the current bidder; ends the auction when only the high
    /// bidder remains.</summary>
    public bool PassBid(out string reason)
    {
        reason = "ok";
        var r = Engine.Apply(_state, new Action("PASS_BID"));
        if (!r.Ok) { reason = $"{r.Code} {r.Context}"; return false; }
        _state = r.State!; return true;
    }

    /// <summary>Apply a trade that BOTH players have agreed to (the consent happens out of band via offer/
    /// accept frames). Because TRADE is deterministic and acts from the current seat, every peer that calls
    /// this with the same (pid, counterparty, amount, choice) lands on the identical state — so the two
    /// sessions stay in lock-step exactly like a signed move. Returns false (state unchanged) if the engine
    /// rejects the trade (wrong owner, insolvent, buildings present, not the post-roll phase, …).</summary>
    public bool Trade(int pid, int counterparty, long amount, string choice, out string reason)
    {
        reason = "ok";
        var r = Engine.Apply(_state, new Action("TRADE") { PropertyId = pid, SeatIndex = counterparty, Amount = amount, Choice = choice });
        if (!r.Ok) { reason = $"{r.Code} {r.Context}"; return false; }
        _state = r.State!;
        return true;
    }

    private static byte[] Payload(string action, int propertyId, string? choice, int[]? dice, byte[] beacon)
    {
        // canonical, replayable move bytes wrapped in the typed protocol (same idea as GamePlay)
        var inner = new List<byte>();
        if (action == "ROLL" && dice is not null) { inner.Add((byte)dice[0]); inner.Add((byte)dice[1]); inner.AddRange(beacon); }
        else
        {
            var t = System.Text.Encoding.ASCII.GetBytes(action);
            inner.Add((byte)t.Length); inner.AddRange(t);
            inner.AddRange(new[] { (byte)(propertyId >> 24), (byte)(propertyId >> 16), (byte)(propertyId >> 8), (byte)propertyId });
            if (choice != null) { var c = System.Text.Encoding.ASCII.GetBytes(choice); inner.Add((byte)c.Length); inner.AddRange(c); }
        }
        return TxProtocol.Stamp(action == "ROLL" ? TxType.Reveal : TxType.Move, inner.ToArray());
    }

    // ---- wire format: a MovePacket serialises to bytes for the network and parses back EXACTLY, so two
    // separate machines exchange moves over P2P and each still re-verifies dice + signature + legality.
    public static byte[] Encode(MovePacket p)
    {
        var o = new List<byte>();
        void U16(int n) { o.Add((byte)((n >> 8) & 0xff)); o.Add((byte)(n & 0xff)); }
        void Str(string? s) { var b = s is null ? System.Array.Empty<byte>() : System.Text.Encoding.UTF8.GetBytes(s); o.Add((byte)b.Length); o.AddRange(b); }
        void Blob(byte[]? b) { b ??= System.Array.Empty<byte>(); U16(b.Length); o.AddRange(b); }
        Str(p.Action); U16(p.Seat); U16(p.Turn); U16(p.PropertyId); Str(p.Choice);
        o.Add((byte)(p.Dice is null ? 0 : 1)); if (p.Dice is not null) { o.Add((byte)p.Dice[0]); o.Add((byte)p.Dice[1]); }
        o.Add((byte)(p.Commits?.Count ?? 0)); foreach (var c in p.Commits ?? new List<Commitment>()) { U16(c.Seat); Blob(c.C); }
        o.Add((byte)(p.Reveals?.Count ?? 0)); foreach (var r in p.Reveals ?? new List<Reveal>()) { U16(r.Seat); Blob(r.Secret); }
        Blob(p.Payload); Blob(p.Sig); Blob(p.SeatPub);
        return o.ToArray();
    }

    public static MovePacket Decode(byte[] data)
    {
        int i = 0;
        int U16() { int n = (data[i] << 8) | data[i + 1]; i += 2; return n; }
        string Str() { int len = data[i++]; var s = System.Text.Encoding.UTF8.GetString(data, i, len); i += len; return s; }
        byte[] Blob() { int len = U16(); var b = data[i..(i + len)]; i += len; return b; }
        string action = Str(); int seat = U16(); int turn = U16(); int pid = U16();
        string choiceRaw = Str(); string? choice = choiceRaw.Length == 0 ? null : choiceRaw;
        int[]? dice = null; if (data[i++] == 1) { dice = new[] { (int)data[i], (int)data[i + 1] }; i += 2; }
        int nc = data[i++]; var commits = new List<Commitment>(); for (int k = 0; k < nc; k++) { int sn = U16(); commits.Add(new Commitment(sn, Blob())); }
        int nr = data[i++]; var reveals = new List<Reveal>(); for (int k = 0; k < nr; k++) { int sn = U16(); reveals.Add(new Reveal(sn, Blob())); }
        byte[] payload = Blob(); byte[] sig = Blob(); byte[] seatPub = Blob();
        return new MovePacket(action, seat, turn, pid, choice, dice,
            commits.Count > 0 ? commits : null, reveals.Count > 0 ? reveals : null, payload, sig, seatPub);
    }
}
