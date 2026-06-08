// Estates.Core/Vault.cs — a 2-of-2 VAULT with a MANDATORY pre-signed nLockTime recovery. ABSOLUTE money
// rule: before a single sat is locked into a {owner, other} 2-of-2, BOTH parties sign a recovery
// transaction that returns 100% of the funds to the OWNER after a future locktime. The owner keeps that
// fully-signed recovery; if the other party ever vanishes, the owner broadcasts it once the locktime
// passes and reclaims everything unilaterally. No sat can ever be stranded.
namespace Estates.Core;

public static class Vault
{
    private const long Final = 0xfffffffe;   // sequence < 0xffffffff so nLockTime is enforced

    /// <summary>A vault's pre-signed recovery: the 2-of-2 spend back to the owner, signed by both, with a
    /// future locktime. Hold it from funding time; broadcast after locktime to reclaim 100%.</summary>
    public sealed record Recovery(NativeTx Tx, byte[] OwnerSig, byte[] OtherSig, byte[] LockScript, long Value, long LockTime);

    /// <summary>The 2-of-2 vault locking script for {owner, other}.</summary>
    public static byte[] LockScript(byte[] ownerPub, byte[] otherPub) => Multisig.Lock2of2(ownerPub, otherPub);

    /// <summary>Build + dual-sign the recovery that refunds 100% (minus fee) to `ownerRefundScript` after
    /// `lockTime`. Both private keys are needed AT FUNDING — that is the whole point: the owner leaves the
    /// table holding a recovery no one else has to cooperate on later.</summary>
    public static Recovery BuildRecovery(string fundTxid, int vout, long value, byte[] ownerPub, byte[] otherPub,
                                         byte[] ownerRefundScript, long lockTime, byte[] ownerPriv, byte[] otherPriv, long fee)
    {
        byte[] lockScript = Multisig.Lock2of2(ownerPub, otherPub);
        long pay = value - fee; if (pay < 0) pay = 0;
        var tx = new NativeTx(2,
            new[] { new TxInputN(fundTxid, vout, System.Array.Empty<byte>(), Final) },
            new[] { new TxOutputN(pay, ownerRefundScript) }, lockTime);
        byte[] ownerSig = Multisig.Sign(tx, 0, lockScript, value, ownerPriv);
        byte[] otherSig = Multisig.Sign(tx, 0, lockScript, value, otherPriv);
        return new Recovery(tx, ownerSig, otherSig, lockScript, value, lockTime);
    }

    /// <summary>Verify a held recovery is valid + actually time-locked + actually reclaimable: both
    /// signatures check, a non-zero locktime is set, and the input is non-final so the locktime binds.</summary>
    public static bool VerifyRecovery(Recovery r, byte[] ownerPub, byte[] otherPub)
        => r.LockTime > 0 && r.Tx.Inputs[0].Sequence < 0xffffffff
           && Multisig.Verify2of2(r.Tx, 0, r.LockScript, r.Value, r.OwnerSig, r.OtherSig, ownerPub, otherPub);

    /// <summary>The final broadcastable recovery transaction (OP_0 + both sigs in the input).</summary>
    public static NativeTx Finalize(Recovery r)
    {
        byte[] unlock = Multisig.Unlock2of2(r.OwnerSig, r.OtherSig);
        return new NativeTx(2,
            new[] { new TxInputN(r.Tx.Inputs[0].PrevTxid, r.Tx.Inputs[0].PrevVout, unlock, Final) },
            System.Linq.Enumerable.ToArray(r.Tx.Outputs), r.LockTime);
    }
}
