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
}
