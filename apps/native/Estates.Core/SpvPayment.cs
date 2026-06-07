// Estates.Core/SpvPayment.cs — the online SPV payment exchange (the capstone, per the SPV appendix).
// The payer (Alice) hands the payee (Bob) the payment transaction PLUS a merkle-proof envelope for
// every input it spends — proof those input coins were mined. Bob VERIFIES each envelope against the
// headers he already holds and accepts the payment INSTANTLY (always online, IP-to-IP), with no
// blockchain-node query and no waiting.
// "Alice already has her merkle proof and gives it to Bob." (Full unlocking-script satisfaction is the
// hardening step; this proves the inputs are real, mined, existent coins and totals what Bob is paid.)
namespace Estates.Core;

public static class SpvPayment
{
    public sealed record Result(bool Ok, long PaidToMe, string Reason);

    /// <summary>Verify an incoming payment: every input must arrive with a valid SPV envelope (its prior
    /// transaction + merkle proof + header) proving it was mined and that the spent output really
    /// exists; then total what the payment pays to my owned scripts.</summary>
    public static Result VerifyIncoming(byte[] rawTx, IReadOnlyList<SpvEnvelope> inputProofs, ISet<string> myScripts)
    {
        var tx = Tx.Parse(rawTx);
        if (tx is null) return new(false, 0, "payment tx malformed");
        if (tx.Inputs.Count == 0 || tx.Outputs.Count == 0) return new(false, 0, "empty tx");

        var proven = new Dictionary<string, NativeTx>();
        foreach (var env in inputProofs)
        {
            if (!env.Verify()) return new(false, 0, "an input's merkle proof failed");   // not a mined coin
            var ptx = Tx.Parse(env.RawTx);
            if (ptx is not null) proven[Tx.Txid(ptx)] = ptx;
        }
        foreach (var i in tx.Inputs)
        {
            if (!proven.TryGetValue(i.PrevTxid, out var ptx)) return new(false, 0, "missing merkle proof for an input");
            if (i.PrevVout < 0 || i.PrevVout >= ptx.Outputs.Count) return new(false, 0, "input spends a non-existent output");
        }
        long paid = 0;
        foreach (var o in tx.Outputs) if (myScripts.Contains(Tx.ToHex(o.Script))) paid += o.Value;
        return new(true, paid, "accepted");
    }
}
