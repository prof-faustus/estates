// Estates.Core/MoveAuth.cs — every move is authenticated by the seat that made it.
//
// The last leg of the "everyone hostile, others always collude" model. The beacon already stops anyone
// biasing the dice and the engine already rejects illegal moves; MoveAuth stops a peer from FORGING another
// player's move. Each action is ECDSA-signed (over turn‖seat‖action‖on-chain-payload) by the acting seat's
// key, and any peer verifies that signature against that seat's known pubkey before accepting the move into
// the shared transcript. A move not signed by its rightful seat is rejected. (On-chain this is the same
// signature the carrier tx already carries; MoveAuth exposes it as the P2P move-authorisation primitive.)
using System.Security.Cryptography;

namespace Estates.Core;

/// <summary>A move plus the acting seat's signature over it and the pubkey that signature must verify under.</summary>
public sealed record SignedMove(GameMove Move, byte[] Signature, byte[] SeatPub);

public static class MoveAuth
{
    /// <summary>Canonical digest a seat signs to authorise its move: turn ‖ seat ‖ action ‖ on-chain payload.</summary>
    public static byte[] MoveDigest(GameMove m)
    {
        var b = new List<byte>();
        b.AddRange(U32(m.Turn)); b.Add((byte)m.Seat);
        var act = System.Text.Encoding.ASCII.GetBytes(m.Action); b.Add((byte)act.Length); b.AddRange(act);
        b.AddRange(m.OnChainPayload);
        return SHA256.HashData(b.ToArray());
    }

    /// <summary>Sign a move with the acting seat's key.</summary>
    public static SignedMove Sign(GameMove m, SeatKey key)
        => new(m, EcdsaSign.SignPrehashDer(key.Priv, MoveDigest(m)), key.Pub);

    /// <summary>Verify a move was signed by `expectedSeatPub` (the seat that's allowed to make it).</summary>
    public static bool Verify(SignedMove sm, byte[] expectedSeatPub)
        => sm.SeatPub.AsSpan().SequenceEqual(expectedSeatPub)
           && EcdsaSign.VerifyDerPrehash(sm.SeatPub, MoveDigest(sm.Move), sm.Signature);

    /// <summary>Sign every real move (skip the GAME_START system fact) by its acting seat.</summary>
    public static List<SignedMove> SignGame(GameResult g, SeatKey[] keys)
        => g.Moves.Where(m => m.Action != "GAME_START").Select(m => Sign(m, keys[m.Seat])).ToList();

    /// <summary>Verify every signed move is authentic (signed by the correct seat). ok = none rejected.</summary>
    public static (bool ok, int verified, int rejected) VerifyGame(IEnumerable<SignedMove> signed, SeatKey[] keys)
    {
        int v = 0, r = 0;
        foreach (var sm in signed)
        {
            if (sm.Move.Seat >= 0 && sm.Move.Seat < keys.Length && Verify(sm, keys[sm.Move.Seat].Pub)) v++;
            else r++;
        }
        return (r == 0, v, r);
    }

    private static byte[] U32(int n) => new[] { (byte)(n >> 24), (byte)(n >> 16), (byte)(n >> 8), (byte)n };
}
