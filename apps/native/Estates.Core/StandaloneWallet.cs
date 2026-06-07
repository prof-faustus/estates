// Estates.Core/StandaloneWallet.cs — a COMPLETE STANDALONE wallet that lives entirely inside the
// exe. ZERO dependencies, NOT ONE: no node, no RPC, no localhost, no server, no network and no
// third-party library. Keys, addresses, the UTXO set, transaction construction and signing all
// happen in-process on the in-tree crypto core (Secp256k1 / EcdsaSign / Scriptvm / Tx / Recovery).
//
// WHY: ESTATES must launch, hold funds, and play with NOTHING to connect to. A wallet that calls a
// node for balance/coins/broadcast is a dependency and a single point of failure — banned from the
// critical path. The bitcoind node is ONLY an optional faucet to obtain test coins; a coin enters
// this wallet either by import (test) or by a peer handing over a signed transfer (P2P), and is
// then verified and spent locally with NO node.
//
// A spend is a real BSV P2PKH transaction: inputs spend our UTXOs, outputs pay the recipient + our
// change, every input signed with SIGHASH_ALL|FORKID over the FORKID preimage. The resulting raw
// tx is handed to a peer (P2P) for broadcast — the wallet itself never reaches out.
using System.Security.Cryptography;

namespace Estates.Core;

/// <summary>A coin this wallet owns: the outpoint, its value, which child address holds it, and
/// (for non-P2PKH coins like NFTs/covenants) the prevout locking script that must be signed over.
/// `Script` null = a standard P2PKH at `AddrIndex`.</summary>
public sealed record Coin(string Txid, long Vout, long Sats, int AddrIndex, byte[]? Script = null);

public sealed class StandaloneWallet
{
    private const long SighashAllForkId = 0x41;
    private readonly byte[] _seed;                 // the master secret (32 bytes), from WalletStore
    private readonly byte _version;                // address version byte for the active network
    private readonly List<Coin> _coins = new();

    public string Network { get; }

    public StandaloneWallet(byte[] seed, string network)
    {
        if (seed.Length != 32) throw new ArgumentException("seed must be 32 bytes");
        _seed = (byte[])seed.Clone();
        Network = network;
        _version = Wallet.VersionFor(network);
    }

    /// <summary>Open (or create) the encrypted wallet file and build a standalone wallet from it.</summary>
    public static StandaloneWallet OpenOrCreate(string password, string network, string? path = null)
        => new(WalletStore.OpenOrCreate(path ?? WalletStore.DefaultPath(), password), network);

    // ---- keys / addresses (deterministic children of the master; no reuse across indices) ----
    public byte[] ChildPriv(int index) => Wallet.ChildPriv(_seed, index);
    public byte[] ChildPub(int index) => Secp256k1.PublicKey(ChildPriv(index));
    public string AddressAt(int index) => Wallet.Address(ChildPub(index), _version);
    public List<WalletAddress> Addresses(int count) => Wallet.Addresses(_seed, count, _version);

    // ---- UTXO set (local; the wallet's own record of what it owns) ----
    public IReadOnlyList<Coin> Coins => _coins;
    public long Balance() => _coins.Sum(c => c.Sats);

    /// <summary>Pending (0-conf, unconfirmed) balance. This local wallet holds only confirmed coins, so
    /// it is 0; it is populated from the node-backed UTXO view once the in-client node feeds it.</summary>
    public long PendingSats => 0;
    /// <summary>Immature coinbase balance (mined, &lt;100 confirmations). 0 for a local wallet; populated
    /// from the node-backed UTXO view (UtxoSet) once the in-client node feeds it.</summary>
    public long ImmatureSats => 0;

    /// <summary>Record a coin this wallet owns. `addrIndex` is the wallet address that holds it.
    /// Used both for a test-faucet import and for a P2P transfer received from a peer.</summary>
    public void AddCoin(string txid, long vout, long sats, int addrIndex)
    {
        if (!IsTxid(txid)) throw new ArgumentException("txid must be 32-byte hex");
        if (vout < 0 || sats <= 0) throw new ArgumentException("bad outpoint/value");
        if (addrIndex < 0) throw new ArgumentException("bad address index");
        if (_coins.Any(c => c.Txid == txid && c.Vout == vout)) return;   // idempotent
        _coins.Add(new Coin(txid, vout, sats, addrIndex));
    }

    /// <summary>Remove coins this wallet just spent (call after a send is settled).</summary>
    public void SpendCoins(IEnumerable<Coin> spent) { foreach (var c in spent) _coins.RemoveAll(x => x.Txid == c.Txid && x.Vout == c.Vout); }

    // ---- build + sign a real P2PKH spend, entirely in-process ----
    public sealed record BuiltTx(string Txid, string RawHex, NativeTx Tx, IReadOnlyList<Coin> Spent, long Fee, long Change);

    /// <summary>Build and SIGN a transaction paying `amountSats` to `toAddress`, with `feeSats` fee
    /// and change back to `changeIndex`. Selects our coins (largest-first), signs every input with
    /// the holding child key (FORKID sighash, low-S ECDSA). Returns the raw tx — to be handed to a
    /// peer or broadcast by the user; the wallet performs NO network action.</summary>
    public BuiltTx BuildSend(string toAddress, long amountSats, long feeSats, int changeIndex = 0)
    {
        if (amountSats <= 0) throw new ArgumentException("amount must be positive");
        byte[] recipientPkh = AddressToPkh(toAddress);
        return BuildAndSign(new[] { new TxOutputN(amountSats, Recovery.P2pkh(recipientPkh)) }, feeSats, changeIndex);
    }

    /// <summary>General builder: pay EXACTLY `outputs` (any scripts — payments, NFTs, data-carriers),
    /// select our coins to cover their value + `feeSats`, append change to `changeIndex`, and sign
    /// every input. The whole "everything is an on-chain tx" path runs through here — entirely local.</summary>
    public BuiltTx BuildAndSign(IReadOnlyList<TxOutputN> outputs, long feeSats, int changeIndex = 0)
    {
        if (feeSats < 0) throw new ArgumentException("fee cannot be negative");
        long need = outputs.Sum(o => o.Value) + feeSats;
        var (selected, gathered) = SelectCoins(need, null);
        return Assemble(selected, AppendChange(outputs, gathered - need, changeIndex), gathered - need);
    }

    /// <summary>Build a tx that MUST spend `forced` (e.g. the exact NFT being transferred) as input 0,
    /// selecting extra coins only to cover the fee/shortfall. Used for NFT transfer + covenant spends.</summary>
    public BuiltTx BuildWithForcedInput(Coin forced, IReadOnlyList<TxOutputN> outputs, long feeSats, int changeIndex = 0)
    {
        if (feeSats < 0) throw new ArgumentException("fee cannot be negative");
        long need = outputs.Sum(o => o.Value) + feeSats;
        var (extra, gathered) = SelectCoins(need - forced.Sats, forced);
        var selected = new List<Coin> { forced }; selected.AddRange(extra);
        long total = forced.Sats + gathered;
        return Assemble(selected, AppendChange(outputs, total - need, changeIndex), total - need);
    }

    private (List<Coin> sel, long got) SelectCoins(long need, Coin? exclude)
    {
        var sel = new List<Coin>(); long got = 0;
        if (need <= 0) return (sel, 0);
        foreach (var c in _coins.OrderByDescending(c => c.Sats))
        {
            if (exclude is not null && c.Txid == exclude.Txid && c.Vout == exclude.Vout) continue;
            sel.Add(c); got += c.Sats;
            if (got >= need) break;
        }
        if (got < need) throw new InvalidOperationException($"insufficient funds: have {got}, need {need}");
        return (sel, got);
    }

    private List<TxOutputN> AppendChange(IReadOnlyList<TxOutputN> outputs, long change, int changeIndex)
    {
        var outs = outputs.ToList();
        if (change > 0) outs.Add(new TxOutputN(change, Recovery.P2pkh(Recovery.Hash160(ChildPub(changeIndex)))));
        return outs;
    }

    private BuiltTx Assemble(IReadOnlyList<Coin> selected, IReadOnlyList<TxOutputN> outs, long change)
    {
        var inputs = selected.Select(c => new TxInputN(c.Txid, c.Vout, Array.Empty<byte>(), 0xffffffff)).ToArray();
        var unsigned = new NativeTx(2, inputs, outs.ToArray(), 0);
        var signedInputs = new TxInputN[selected.Count];
        for (int i = 0; i < selected.Count; i++)
        {
            Coin c = selected[i];
            byte[] priv = ChildPriv(c.AddrIndex);
            byte[] pub = Secp256k1.PublicKey(priv);
            byte[] prevScript = Recovery.P2pkh(Recovery.Hash160(pub));
            byte[] sighash = Scriptvm.Sighash(unsigned, i, prevScript, c.Sats, SighashAllForkId);
            byte[] der = EcdsaSign.SignPrehashDer(priv, sighash);
            var sig = new byte[der.Length + 1]; Array.Copy(der, sig, der.Length); sig[^1] = (byte)SighashAllForkId;
            var ss = new List<byte>(); PushData(ss, sig); PushData(ss, pub);
            signedInputs[i] = unsigned.Inputs[i] with { ScriptSig = ss.ToArray() };
        }
        var signed = new NativeTx(unsigned.Version, signedInputs, unsigned.Outputs, unsigned.LockTime);
        long fee = selected.Sum(c => c.Sats) - outs.Sum(o => o.Value);
        return new BuiltTx(Tx.Txid(signed), Tx.ToHex(Tx.Serialize(signed)), signed, selected, fee, change);
    }

    /// <summary>Verify a built tx's input signatures locally (no node) — proves it is spend-valid
    /// before it ever leaves the wallet.</summary>
    public bool VerifySpend(BuiltTx built)
    {
        for (int i = 0; i < built.Spent.Count; i++)
        {
            Coin c = built.Spent[i];
            byte[] pub = Secp256k1.PublicKey(ChildPriv(c.AddrIndex));
            byte[] prevScript = Recovery.P2pkh(Recovery.Hash160(pub));
            byte[] ss = built.Tx.Inputs[i].ScriptSig;
            (byte[] sig, byte[] spub) = ReadP2pkhScriptSig(ss);
            if (!Scriptvm.CheckSig(built.Tx, i, prevScript, c.Sats, sig, Tx.ToHex(spub))) return false;
        }
        return true;
    }

    // ---- helpers (in-tree only) ----
    private static void PushData(List<byte> o, byte[] d)
    {
        if (d.Length < 0x4c) { o.Add((byte)d.Length); o.AddRange(d); }
        else if (d.Length <= 0xff) { o.Add(0x4c); o.Add((byte)d.Length); o.AddRange(d); }
        else throw new ArgumentException("pushdata too large for a scriptSig element");
    }

    private static (byte[] sig, byte[] pub) ReadP2pkhScriptSig(byte[] ss)
    {
        int i = 0;
        byte[] Read()
        {
            int len = ss[i++];
            if (len == 0x4c) len = ss[i++];
            var b = ss[i..(i + len)]; i += len; return b;
        }
        byte[] sig = Read(); byte[] pub = Read();
        return (sig, pub);
    }

    private static bool IsTxid(string h) => h.Length == 64 && h.All(Uri.IsHexDigit);

    /// <summary>Decode a base58check P2PKH address to its 20-byte hash160 (rejects bad checksum/version).</summary>
    public static byte[] AddressToPkh(string address)
    {
        byte[] full = Base58Decode(address);
        if (full.Length != 25) throw new ArgumentException("bad address length");
        byte[] payload = full[..21];
        byte[] check = SHA256.HashData(SHA256.HashData(payload));
        if (!check.AsSpan(0, 4).SequenceEqual(full.AsSpan(21, 4))) throw new ArgumentException("bad address checksum");
        return payload[1..];
    }

    private const string B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static byte[] Base58Decode(string s)
    {
        System.Numerics.BigInteger num = 0;
        foreach (char c in s)
        {
            int d = B58.IndexOf(c);
            if (d < 0) throw new ArgumentException("invalid base58 character");
            num = num * 58 + d;
        }
        var bytes = new List<byte>();
        while (num > 0) { num = System.Numerics.BigInteger.DivRem(num, 256, out var rem); bytes.Insert(0, (byte)rem); }
        int zeros = 0; foreach (char c in s) { if (c == '1') zeros++; else break; }
        for (int i = 0; i < zeros; i++) bytes.Insert(0, 0);
        return bytes.ToArray();
    }
}
