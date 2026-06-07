// Estates.Core/Beacon.cs — native dealerless dice beacon.
// commit = SHA256(secret); seed = SHA256(reveals-in-seat-order ‖
// turnIndex(BE) ‖ prevBeacon); each die = first byte < 252 of HMAC-SHA256(seed,
// label(BE) ‖ counter(BE)) mapped (b%6)+1 (rejection sampling). verifyRollEntry
// re-checks the commitment-verified reveal set and the claimed dice. This is the
// last crypto primitive a native client needs to REPLAY a live game's rolls.
using System.Security.Cryptography;

namespace Estates.Core;

public sealed record Reveal(int Seat, byte[] Secret);
public sealed record Commitment(int Seat, byte[] C);

public static class Beacon
{
    public static readonly byte[] ZeroBeacon = new byte[32];

    private static byte[] U32Be(long n) => new[] { (byte)((n >> 24) & 0xff), (byte)((n >> 16) & 0xff), (byte)((n >> 8) & 0xff), (byte)(n & 0xff) };
    private static byte[] Concat(params byte[][] parts) { var o = new List<byte>(); foreach (var p in parts) o.AddRange(p); return o.ToArray(); }

    public static byte[] Commit(byte[] secret) { using var sha = SHA256.Create(); return sha.ComputeHash(secret); }

    public static bool VerifyReveal(byte[] secret, byte[] commitment)
    {
        var c = Commit(secret);
        if (c.Length != commitment.Length) return false;
        int diff = 0; for (int i = 0; i < c.Length; i++) diff |= c[i] ^ commitment[i];
        return diff == 0;
    }

    public static byte[] BeaconSeed(IReadOnlyList<Reveal> reveals, long turnIndex, byte[] prevBeacon)
    {
        var ordered = reveals.OrderBy(r => r.Seat).ToList();
        var bytes = new List<byte>();
        foreach (var r in ordered) bytes.AddRange(r.Secret);
        bytes.AddRange(U32Be(turnIndex)); bytes.AddRange(prevBeacon);
        using var sha = SHA256.Create();
        return sha.ComputeHash(bytes.ToArray());
    }

    private static int DrawDie(byte[] seed, int label)
    {
        using var hmac = new HMACSHA256(seed);
        for (long counter = 0; counter < (1 << 20); counter++)
        {
            var mac = hmac.ComputeHash(Concat(U32Be(label), U32Be(counter)));
            foreach (var b in mac) if (b < 252) return (b % 6) + 1;
        }
        throw new InvalidOperationException("beacon: exhausted PRF");
    }

    /// <summary>Resolve a roll: dice + the chained beacon (= the seed).</summary>
    public static (int[] Dice, byte[] Beacon) Roll(IReadOnlyList<Reveal> reveals, long turnIndex, byte[] prevBeacon)
    {
        var seed = BeaconSeed(reveals, turnIndex, prevBeacon);
        return (new[] { DrawDie(seed, 0), DrawDie(seed, 1) }, seed);
    }

    /// <summary>Verify a roll entry exactly like the TS reference: one commitment
    /// per live seat (no dup), reveals open their commitments (no non-live/dup), ≥1
    /// reveal, dice derived ONLY from the verified set (matching any claim). Total.</summary>
    public static (bool Ok, string Reason, int[]? Dice, byte[]? Beacon) VerifyRollEntry(
        IReadOnlyList<Commitment> commits, IReadOnlyList<Reveal> reveals, IReadOnlyList<int> liveSeats,
        long turnIndex, byte[] prevBeacon, int[]? claimedDice = null)
    {
        try
        {
            var live = new HashSet<int>(liveSeats);
            var cSeats = commits.Select(c => c.Seat).ToList();
            if (new HashSet<int>(cSeats).Count != cSeats.Count) return (false, "duplicate commitment seat", null, null);
            foreach (var c in commits) if (!live.Contains(c.Seat)) return (false, $"commitment from a non-live seat {c.Seat}", null, null);
            var cmap = commits.ToDictionary(c => c.Seat, c => c.C);
            var rSeats = reveals.Select(r => r.Seat).ToList();
            if (new HashSet<int>(rSeats).Count != rSeats.Count) return (false, "duplicate reveal seat", null, null);
            var verified = new List<Reveal>();
            foreach (var rv in reveals)
            {
                if (!live.Contains(rv.Seat)) return (false, $"reveal from a non-live / non-seat {rv.Seat}", null, null);
                if (!cmap.TryGetValue(rv.Seat, out var c)) return (false, $"reveal from seat {rv.Seat} with no prior commitment", null, null);
                if (!VerifyReveal(rv.Secret, c)) return (false, $"reveal from seat {rv.Seat} does not open its commitment", null, null);
                verified.Add(rv);
            }
            if (verified.Count == 0) return (false, "no honest reveal", null, null);
            var (dice, beacon) = Roll(verified, turnIndex, prevBeacon);
            if (claimedDice != null && (claimedDice.Length != 2 || claimedDice[0] != dice[0] || claimedDice[1] != dice[1]))
                return (false, "claimed dice do not match the beacon", null, null);
            return (true, "verified", dice, beacon);
        }
        catch (Exception ex) { return (false, "threw: " + ex.Message, null, null); }
    }
}
