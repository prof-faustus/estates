// Estates.Core/GameTranscript.cs — trustless game follower: reconstruct + verify a whole Estates game
// from its on-chain transcript ALONE, trusting no one.
//
// ESTATES has no server and no off-chain referee — "game state IS the verified on-chain/signed transcript."
// This is the code that makes that true: given the move stream (each move's typed on-chain payload, plus the
// committed-then-revealed deck order and, per roll, the beacon commits+reveals), GameTranscript.Verify:
//   1. rebuilds the initial state from the revealed deck order,
//   2. for every ROLL, RE-DERIVES the dice from the reveals via the beacon (it does NOT trust the claimed
//      dice — it recomputes them and checks they match),
//   3. decodes every other action straight from its on-chain payload and re-applies it through the pure Engine,
//   4. confirms the replay reaches the SAME winner the transcript claims.
// If any roll was biased, any move was illegal, or the winner was misreported, Verify fails with a reason.
namespace Estates.Core;

public sealed record TranscriptResult(bool Ok, string Reason, int? Winner, int RollsVerified, int MovesReplayed);

public static class GameTranscript
{
    /// <summary>Independently verify a game from its transcript. Trustless: dice are re-derived from the
    /// beacon reveals, actions are decoded from their on-chain payloads, and the engine is re-run from a
    /// fresh initial state. Returns the verified winner, or a failure reason. Pure — no node, no network.</summary>
    public static TranscriptResult Verify(GameResult g)
    {
        try
        {
            var state = Engine.InitialState(g.Network, g.Seats, g.BankReserve,
                new Dictionary<string, List<int>>(g.DeckOrder), requireFairDecks: true);
            state.AuctionsEnabled = g.AuctionsEnabled;   // so a DECLINE replays into an auction, as it did live
            byte[] prevBeacon = Beacon.ZeroBeacon;
            int rolls = 0, replayed = 0;

            foreach (var m in g.Moves)
            {
                if (m.Action == "GAME_START") continue;

                if (m.Action == "ROLL")
                {
                    var live = state.Seats.Where(x => !x.Bankrupt).Select(x => x.Id).ToList();
                    var v = Beacon.VerifyRollEntry(
                        m.Commits ?? new List<Commitment>(), m.Reveals ?? new List<Reveal>(),
                        live, state.TurnIndex, prevBeacon, m.Dice);   // re-derive + check claimed dice
                    if (!v.Ok || v.Dice is null)
                        return new TranscriptResult(false, $"roll@turn {state.TurnIndex}: {v.Reason}", null, rolls, replayed);
                    prevBeacon = v.Beacon!;
                    var r = Engine.Apply(state, new Action("ROLL") { Dice = v.Dice });
                    if (!r.Ok) return new TranscriptResult(false, $"engine rejected ROLL: {r.Code} {r.Context}", null, rolls, replayed);
                    state = r.State!; rolls++; replayed++;
                    continue;
                }

                var action = DecodeFromPayload(m.OnChainPayload);
                if (action is null) return new TranscriptResult(false, $"undecodable on-chain payload for {m.Action}", null, rolls, replayed);
                var rr = Engine.Apply(state, action);
                if (!rr.Ok) return new TranscriptResult(false, $"engine rejected {action.Type}: {rr.Code} {rr.Context}", null, rolls, replayed);
                state = rr.State!; replayed++;
            }

            if (state.Winner != g.Winner)
                return new TranscriptResult(false, $"winner mismatch: replay={state.Winner} claimed={g.Winner}", state.Winner, rolls, replayed);
            if (g.Finished && state.Phase != "GAME_OVER")
                return new TranscriptResult(false, $"transcript claims finished but replay phase={state.Phase}", state.Winner, rolls, replayed);
            return new TranscriptResult(true, "verified", state.Winner, rolls, replayed);
        }
        catch (Exception e) { return new TranscriptResult(false, "threw: " + e.Message, null, 0, 0); }
    }

    /// <summary>Decode the engine Action from a move's typed on-chain payload (the canonical record).</summary>
    private static Action? DecodeFromPayload(byte[] onchain)
    {
        var hdr = TxProtocol.Read(onchain);
        if (hdr is null) return null;
        byte[] p = hdr.Value.payload;
        if (p.Length < 1) return null;
        int i = 0;
        int typeLen = p[i++];
        if (i + typeLen + 4 > p.Length) return null;
        string type = System.Text.Encoding.ASCII.GetString(p, i, typeLen); i += typeLen;
        int propId = (p[i] << 24) | (p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3]; i += 4;
        string? choice = null; int seatIndex = 0; long amount = 0;
        if (type is "TRADE" or "BID")
        {
            // extended layout: <choiceLen><choice><seatIndex(4)><amount(8)>
            if (i >= p.Length) return null;
            int cl = p[i++]; if (i + cl + 12 > p.Length) return null;
            if (cl > 0) choice = System.Text.Encoding.ASCII.GetString(p, i, cl);
            i += cl;
            seatIndex = (p[i] << 24) | (p[i + 1] << 16) | (p[i + 2] << 8) | p[i + 3]; i += 4;
            for (int k = 0; k < 8; k++) amount = (amount << 8) | p[i++];
        }
        else if (i < p.Length) { int cl = p[i++]; if (i + cl <= p.Length) choice = System.Text.Encoding.ASCII.GetString(p, i, cl); }
        return type switch
        {
            "BUY" => new Action("BUY"),
            "DECLINE" => new Action("DECLINE"),
            "PAY_TAX" => new Action("PAY_TAX") { Choice = choice ?? "flat" },
            "BUILD" => new Action("BUILD") { PropertyId = propId },
            "SELL_BUILD" => new Action("SELL_BUILD") { PropertyId = propId },
            "MORTGAGE" => new Action("MORTGAGE") { PropertyId = propId },
            "UNMORTGAGE" => new Action("UNMORTGAGE") { PropertyId = propId },
            "TRADE" => new Action("TRADE") { PropertyId = propId, SeatIndex = seatIndex, Amount = amount, Choice = choice },
            "USE_REPRIEVE" => new Action("USE_REPRIEVE"),
            "BID" => new Action("BID") { Amount = amount },
            "PASS_BID" => new Action("PASS_BID"),
            "END_TURN" => new Action("END_TURN"),
            "FORFEIT" => new Action("FORFEIT"),
            _ => new Action(type),
        };
    }
}
