// Estates.Core/WalletEngine.cs — a NODE-BACKED wallet engine: it owns a KeyRing (a fresh address per
// receive, one fixed identity key) and reads its balance STRAIGHT FROM THE NODE'S UTXO LEDGER
// (UtxoSet). There is no manual import — a balance exists only because the node saw the output on the
// chain. It recognizes any output paying one of its derived P2PKH scripts (up to a watch horizon) and
// reports the spendable and immature balances. Every receive address is handed out once, never reused.
namespace Estates.Core;

public sealed class WalletEngine
{
    private readonly KeyRing _ring;
    private readonly int _watch;
    private HashSet<string>? _owned;

    public WalletEngine(byte[] seed32, int watchHorizon = 200)
    {
        _ring = new KeyRing(seed32);
        _watch = watchHorizon < 1 ? 1 : watchHorizon;
    }

    public KeyRing Keys => _ring;
    public byte[] IdentityPub() => _ring.IdentityPub();

    /// <summary>The P2PKH scripts (hex) this wallet owns: identity address + receive indices 1.._watch.
    /// Cached, since each derivation is an EC multiply.</summary>
    public HashSet<string> OwnedScripts()
    {
        if (_owned is not null) return _owned;
        var s = new HashSet<string> { Tx.ToHex(NodeWallet.P2pkhScript(Recovery.Hash160(_ring.IdentityPub()))) };
        for (long i = 1; i <= _watch; i++) s.Add(Tx.ToHex(NodeWallet.P2pkhScript(Recovery.Hash160(_ring.PubAt(i)))));
        _owned = s;
        return s;
    }

    /// <summary>A FRESH receive address (base58check P2PKH) — never reused.</summary>
    public (long index, string address, byte[] pub) NextReceiveAddress(BsvNet net)
    {
        var k = _ring.NextReceive();
        return (k.index, Address.P2pkh(Recovery.Hash160(k.pub), net), k.pub);
    }

    public long Spendable(UtxoSet u) => u.SpendableFor(OwnedScripts());
    public long Immature(UtxoSet u) => u.ImmatureFor(OwnedScripts());
    public long Total(UtxoSet u) => Spendable(u) + Immature(u);
}
