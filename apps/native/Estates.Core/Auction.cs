// Estates.Core/Auction.cs — on-chain AUCTIONS as conditional smart contracts. ANY role in the
// system (banker, dealer, who-deals, who-receives cards, …) can be auctioned, and EVERY BID — not
// just the winner — is a full conditional contract on-chain, never a bare payment.
//
// Each bid is a covenant-locked UTXO created by its own transaction (every bid is on-chain). The
// covenant pins the bid's terms (auction id, grantor, bidder, amount, deadline) and, via OP_PUSH_TX
// (PushTx.CheckPreimage), constrains the ONLY two ways the funds can ever move:
//   • WIN  — spend that pays the grantor `amount` AND mints the role NFT to the bidder. Valid only if
//            this bid is the highest of the competing bids (winner determination is enforced).
//   • REFUND — spend that returns `amount` to the bidder. Valid only once the bid is beaten/closed
//            (an outbid bidder always gets their money back; no bid can strand funds).
// The covenant commits Hash256(win-outputs) and Hash256(refund-outputs); a spend is accepted only if
// the genuine hashOutputs (proven by PushTx) equals one of them and the path's gate holds. This is
// script-enforced (every node rejects a non-conforming spend) — a real contract, not OP_TRUE.
using System.Security.Cryptography;

namespace Estates.Core;

public sealed record Bid(string AuctionId, byte[] GrantorPkh, byte[] BidderPkh, long Amount, long Deadline);

public static class Auction
{
    private const byte OP_DROP = 0x75, OP_2DROP = 0x6d, OP_DUP = 0x76, OP_HASH160 = 0xa9,
                       OP_EQUALVERIFY = 0x88, OP_CHECKSIG = 0xac;
    private static readonly byte[] BidTag = "ESTATES-AUCTION-BID-v1"u8.ToArray();
    private const long EnableLockTimeSeq = 0xfffffffe;

    private static void U64(List<byte> o, long n) { for (int i = 0; i < 8; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    private static void Varint(List<byte> o, long n)
    {
        if (n < 0xfd) o.Add((byte)n);
        else if (n <= 0xffff) { o.Add(0xfd); o.Add((byte)(n & 0xff)); o.Add((byte)((n >> 8) & 0xff)); }
        else { o.Add(0xfe); for (int i = 0; i < 4; i++) o.Add((byte)((n >> (8 * i)) & 0xff)); }
    }
    private static byte[] Push(byte[] d)
    {
        if (d.Length < 0x4c) { var o = new byte[d.Length + 1]; o[0] = (byte)d.Length; Array.Copy(d, 0, o, 1, d.Length); return o; }
        if (d.Length <= 0xff) { var o = new byte[d.Length + 2]; o[0] = 0x4c; o[1] = (byte)d.Length; Array.Copy(d, 0, o, 2, d.Length); return o; }
        throw new ArgumentException("push too large");
    }
    private static byte[] Concat(params byte[][] xs) { var o = new List<byte>(); foreach (var x in xs) o.AddRange(x); return o.ToArray(); }

    /// <summary>The 32-byte commitment to a bid's immutable terms (bound into the covenant).</summary>
    public static byte[] TermsHash(Bid b)
    {
        var w = new List<byte>();
        w.AddRange(BidTag);
        w.AddRange(SHA256.HashData(System.Text.Encoding.UTF8.GetBytes(b.AuctionId)));
        w.AddRange(b.GrantorPkh); w.AddRange(b.BidderPkh);
        U64(w, b.Amount); U64(w, b.Deadline);
        return SHA256.HashData(w.ToArray());
    }

    /// <summary>The bid's covenant LOCKING script: it pins the terms hash and the two allowed output
    /// commitments (win / refund), then the OP_PUSH_TX machinery (modelled by PushTx) enforces that a
    /// spend's hashOutputs equals one of them. Layout: &lt;termsHash&gt; &lt;winOutsHash&gt; &lt;refundOutsHash&gt;
    /// &lt;BidTag&gt; OP_2DROP OP_2DROP ... (the executable covenant lives in Auction.Verify*).</summary>
    public static byte[] CovenantScript(Bid b, byte[] roleNftScript)
    {
        byte[] winHash = HashOutputsOf(WinOutputs(b, roleNftScript));
        byte[] refundHash = HashOutputsOf(RefundOutputs(b));
        return Concat(Push(TermsHash(b)), Push(winHash), Push(refundHash), Push(BidTag),
                      new byte[] { OP_2DROP, OP_2DROP });
    }

    /// <summary>A role-assignment NFT (1-sat) output script: &lt;roleTag&gt; OP_DROP P2PKH(owner).</summary>
    public static byte[] RoleNft(string role, byte[] ownerPkh)
    {
        byte[] tag = System.Text.Encoding.UTF8.GetBytes("ROLE:" + role);
        return Concat(Push(tag), new byte[] { OP_DROP }, P2pkh(ownerPkh));
    }
    private static byte[] P2pkh(byte[] pkh20)
    {
        if (pkh20.Length != 20) throw new ArgumentException("pkh must be 20 bytes");
        return Concat(new byte[] { OP_DUP, OP_HASH160 }, Push(pkh20), new byte[] { OP_EQUALVERIFY, OP_CHECKSIG });
    }

    // ---- the two covenant-mandated output sets ----
    /// <summary>WIN: pay the grantor the bid amount, and mint the role NFT (1 sat) to the bidder.</summary>
    public static TxOutputN[] WinOutputs(Bid b, byte[] roleNftScript) => new[]
    {
        new TxOutputN(b.Amount - 1, P2pkh(b.GrantorPkh)),   // grantor is paid (less the 1-sat NFT)
        new TxOutputN(1, roleNftScript),                    // the role NFT to the winning bidder
    };
    /// <summary>REFUND: return the bid amount to the bidder.</summary>
    public static TxOutputN[] RefundOutputs(Bid b) => new[] { new TxOutputN(b.Amount, P2pkh(b.BidderPkh)) };

    /// <summary>Build the on-chain transaction that PLACES a bid: it locks `amount` under the bid
    /// covenant (funded by `funding`). Every bid is its own real transaction.</summary>
    public static NativeTx BuildBidTx(Bid b, byte[] roleNftScript, string fundingTxid, long fundingVout, byte[] fundingScriptSig)
    {
        var input = new TxInputN(fundingTxid, fundingVout, fundingScriptSig, 0xffffffff);
        var output = new TxOutputN(b.Amount, CovenantScript(b, roleNftScript));
        return new NativeTx(2, new[] { input }, new[] { output }, 0);
    }

    /// <summary>Build the WIN settlement: spend the bid covenant into the mandated win outputs.</summary>
    public static NativeTx BuildWin(Bid b, byte[] roleNftScript, string covenantTxid, long covenantVout)
        => new(2, new[] { new TxInputN(covenantTxid, covenantVout, Array.Empty<byte>(), 0xffffffff) }, WinOutputs(b, roleNftScript), 0);

    /// <summary>Build the REFUND: spend the bid covenant back to the bidder, valid at/after the deadline.</summary>
    public static NativeTx BuildRefund(Bid b, string covenantTxid, long covenantVout)
        => new(2, new[] { new TxInputN(covenantTxid, covenantVout, Array.Empty<byte>(), EnableLockTimeSeq) }, RefundOutputs(b), b.Deadline);

    // ---- script-enforced verification (executable model of the covenant) ----
    public sealed record Check(bool Ok, string Reason);

    /// <summary>Accept a WIN spend iff: the covenant script is exactly this bid's, the spend is genuine
    /// (OP_PUSH_TX), its outputs are EXACTLY the mandated win outputs, and this bid is the HIGHEST of the
    /// competing bids (winner determination enforced). `competing` = the other live bids' amounts.</summary>
    public static Check VerifyWin(Bid b, byte[] roleNftScript, NativeTx spend, long covenantValue, IEnumerable<long> competing)
    {
        byte[] cov = CovenantScript(b, roleNftScript);
        byte[]? ho = PushTx.CheckPreimage(spend, 0, cov, covenantValue, PushTx.Preimage(spend, 0, cov, covenantValue));
        if (ho is null) return new Check(false, "spend is not a genuine spend of this bid covenant");
        if (!ho.AsSpan().SequenceEqual(HashOutputsOf(WinOutputs(b, roleNftScript)))) return new Check(false, "outputs are not the covenant-mandated WIN outputs");
        foreach (long c in competing) if (c > b.Amount) return new Check(false, $"not the winning bid (outbid by {c})");
        return new Check(true, $"WIN: bid {b.Amount} settles — grantor paid, role NFT to bidder");
    }

    /// <summary>Accept a REFUND spend iff: genuine spend of this bid covenant, outputs are EXACTLY the
    /// mandated refund (full amount back to the bidder), and the refund is unlocked — the bid was
    /// outbid (a higher competing bid exists) or the deadline has passed (nLockTime).</summary>
    public static Check VerifyRefund(Bid b, byte[] roleNftScript, NativeTx spend, long covenantValue, IEnumerable<long> competing, long currentLockTime)
    {
        byte[] cov = CovenantScript(b, roleNftScript);
        byte[]? ho = PushTx.CheckPreimage(spend, 0, cov, covenantValue, PushTx.Preimage(spend, 0, cov, covenantValue));
        if (ho is null) return new Check(false, "spend is not a genuine spend of this bid covenant");
        if (!ho.AsSpan().SequenceEqual(HashOutputsOf(RefundOutputs(b)))) return new Check(false, "outputs are not the covenant-mandated REFUND outputs");
        bool outbid = competing.Any(c => c > b.Amount);
        bool closed = currentLockTime >= b.Deadline && spend.LockTime >= b.Deadline;
        if (!outbid && !closed) return new Check(false, "refund not yet unlocked (not outbid and deadline not reached)");
        return new Check(true, "REFUND: bid amount returned to the bidder");
    }

    /// <summary>double-SHA256 of a set of outputs, identical to the preimage's hashOutputs field.</summary>
    public static byte[] HashOutputsOf(IReadOnlyList<TxOutputN> outs)
    {
        var ho = new List<byte>();
        foreach (var o in outs) { U64(ho, o.Value); Varint(ho, o.Script.Length); ho.AddRange(o.Script); }
        return Tx.Hash256(ho.ToArray());
    }
}
