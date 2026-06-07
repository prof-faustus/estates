// Estates.Core/SpvSpend.cs — SEND from the SPV wallet. Selects the wallet's own coins, builds the
// payment transaction, signs each input with its one-time key (FORKID sighash, low-S ECDSA), and
// returns the signed tx PLUS the spent coins' stored merkle-proof envelopes — which the payer hands to
// the payee IP-to-IP so the payee can verify the inputs were real, mined coins (SPV, no node query).
namespace Estates.Core;

public static class SpvSpend
{
    private const long ForkId = 0x41;   // SIGHASH_ALL | FORKID

    public sealed record Built(NativeTx Tx, byte[] Raw, string Txid, List<SpvEnvelope> InputProofs, long Change);

    /// <summary>Build + sign a spend of `amount` to `toScript`, change to `changeScript`. `scriptToKey`
    /// maps each owned P2PKH script (hex) to its (priv, pub). null on insufficient funds.</summary>
    public static Built? Build(SpvWallet w, Dictionary<string, (byte[] priv, byte[] pub)> scriptToKey,
                               byte[] toScript, long amount, long fee, byte[] changeScript)
    {
        if (amount <= 0 || fee < 0) return null;
        long need = amount + fee, sum = 0;
        var chosen = new List<(string txid, int vout, long value, byte[] script)>();
        foreach (var u in System.Linq.Enumerable.OrderByDescending(w.Utxos(), x => x.value))
        {
            if (!scriptToKey.ContainsKey(Tx.ToHex(u.script))) continue;   // must own the key
            chosen.Add(u); sum += u.value;
            if (sum >= need) break;
        }
        if (sum < need) return null;
        long change = sum - need;

        var outs = new List<TxOutputN> { new(amount, toScript) };
        if (change > 0) outs.Add(new TxOutputN(change, changeScript));

        // unsigned skeleton (empty scriptSigs) — the FORKID sighash uses each prevout's script+value, not scriptSigs
        var unsignedIns = new List<TxInputN>();
        foreach (var c in chosen) unsignedIns.Add(new TxInputN(c.txid, c.vout, System.Array.Empty<byte>(), 0xffffffff));
        var unsigned = new NativeTx(2, unsignedIns, outs, 0);

        var signedIns = new List<TxInputN>();
        var proofs = new List<SpvEnvelope>();
        for (int i = 0; i < chosen.Count; i++)
        {
            var c = chosen[i];
            var (priv, pub) = scriptToKey[Tx.ToHex(c.script)];
            byte[] sighash = Scriptvm.Sighash(unsigned, i, c.script, c.value, ForkId);
            byte[] der = EcdsaSign.SignPrehashDer(priv, sighash);
            var sigWithType = new byte[der.Length + 1];
            System.Array.Copy(der, sigWithType, der.Length); sigWithType[^1] = (byte)ForkId;
            var ss = new List<byte>(); Push(ss, sigWithType); Push(ss, pub);
            signedIns.Add(new TxInputN(c.txid, c.vout, ss.ToArray(), 0xffffffff));
            var pr = w.ProofFor(c.txid + ":" + c.vout); if (pr is not null) proofs.Add(pr);
        }
        var signed = new NativeTx(2, signedIns, outs, 0);
        return new Built(signed, Tx.Serialize(signed), Tx.Txid(signed), proofs, change);
    }

    private static void Push(List<byte> o, byte[] d)
    {
        if (d.Length < 0x4c) o.Add((byte)d.Length);
        else if (d.Length <= 0xff) { o.Add(0x4c); o.Add((byte)d.Length); }
        else { o.Add(0x4d); o.Add((byte)(d.Length & 0xff)); o.Add((byte)(d.Length >> 8)); }
        o.AddRange(d);
    }
}
