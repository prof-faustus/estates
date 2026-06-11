// Estates.Core/SpvEnvelope.cs — BSV peer-to-peer SPV, the real model. A coin is delivered as an
// ENVELOPE: the raw transaction + its merkle proof + the block header that proves it was mined. The
// SENDER (Alice) has STORED that envelope and hands it to the payee (Bob) IP-to-IP with the payment.
// Bob's wallet VERIFIES it (merkle branch → header merkle root, and the header meets proof-of-work) and
// STORES it — ALWAYS — so Bob can in turn hand it to whoever he pays. No node query, no chain scan, no
// header IBD: the proof arrives WITH the money over the live IP-to-IP link, so the wallet is instant.
// (Always online; SPV just means the wallet never queries a blockchain node — peers deliver the proof.)
namespace Estates.Core;

public sealed record SpvEnvelope(byte[] RawTx, byte[] Header80, IReadOnlyList<string> Branch, long Index)
{
    public string Txid() { var tx = Tx.Parse(RawTx); return tx is null ? "" : Tx.Txid(tx); }

    /// <summary>Prove the transaction was mined: the merkle proof reaches the header's merkle root AND
    /// the header itself meets its stated proof-of-work. TOTAL — false on any malformed input.</summary>
    public bool Verify()
    {
        var tx = Tx.Parse(RawTx); if (tx is null) return false;
        var hdr = BsvHeaders.Parse(Header80); if (hdr is null || !BsvHeaders.MeetsProofOfWork(hdr)) return false;
        return MerkleProof.Verify(Tx.Txid(tx), Branch, Index, hdr.MerkleRoot);
    }
}

/// <summary>An SPV wallet: it holds the coins it has RECEIVED (each with the stored envelope that proves
/// it), computes balance from its own verified UTXOs, and can produce the stored proof to hand to the
/// next payee. It never asks a node and never scans the chain.</summary>
public sealed class SpvWallet
{
    private readonly HashSet<string> _owned;                                  // owned P2PKH scripts (hex)
    private readonly Dictionary<string, (long value, byte[] script)> _utxos = new();   // outpoint -> CONFIRMED coin
    private readonly Dictionary<string, SpvEnvelope> _proofs = new();         // outpoint -> stored merkle proof
    // The THREE received states are kept strictly separate (the user's rule):
    //  • _utxos/_proofs = CONFIRMED — has a merkle proof to a proof-of-work header; spendable.
    //  • _pending       = UNCONFIRMED — the raw tx arrived but no proof yet; NOT spendable; watched until it
    //                     either gains a proof (→ confirmed) or is flagged a double-spend (→ invalid).
    //  • _invalid       = DOUBLE-SPEND / INVALID — a peer/node reported the input was already spent or the tx
    //                     is otherwise invalid; never spendable; shown so the user knows it failed.
    private readonly Dictionary<string, (long value, byte[] script, byte[] rawTx)> _pending = new();  // outpoint -> UNCONFIRMED
    private readonly Dictionary<string, string> _invalid = new();             // txid -> reason (double-spend / invalid)
    // TOKEN/NFT coins: carrier-script UTXOs whose P2PKH tail is OURS. These are the tokens the wallet HOLDS —
    // identity, deeds, cards — read straight from the wallet's coins (the token IS the coin; no side files).
    // Held SEPARATELY from money so a token coin is NEVER selected/spent as an ordinary fee/payment input.
    private readonly Dictionary<string, (long value, byte[] script)> _tokens = new();   // outpoint -> owned token coin
    private readonly object _lock = new();

    public SpvWallet(IEnumerable<byte[]> ownedScripts)
    {
        _owned = new HashSet<string>();
        foreach (var s in ownedScripts) _owned.Add(Tx.ToHex(s));
    }

    /// <summary>Receive a coin: VERIFY the envelope, then STORE it and credit any outputs paying us.
    /// Returns false (credits nothing) if the proof does not verify.</summary>
    public bool Receive(SpvEnvelope env)
    {
        if (!env.Verify()) return false;
        var tx = Tx.Parse(env.RawTx)!;
        string txid = Tx.Txid(tx);
        lock (_lock)
        {
            for (int v = 0; v < tx.Outputs.Count; v++)
            {
                var sc = tx.Outputs[v].Script;
                string op = txid + ":" + v;
                if (_owned.Contains(Tx.ToHex(sc)))                            // a bare P2PKH we own → MONEY coin
                {
                    _utxos[op] = (tx.Outputs[v].Value, sc);
                    _proofs[op] = env;                                        // stored ALWAYS, for handoff
                    _pending.Remove(op);                                      // UNCONFIRMED → CONFIRMED (proof arrived)
                }
                else if (sc.Length > 25 && _owned.Contains(Tx.ToHex(sc[^25..])))  // <data> OP_DROP P2PKH(ours) → TOKEN coin
                {
                    _tokens[op] = (tx.Outputs[v].Value, sc);
                    _proofs[op] = env;                                        // proof stored so the token can be re-handed
                }
            }
            _invalid.Remove(txid);                                            // a real proof clears any earlier flag
        }
        return true;
    }

    public long Balance() { lock (_lock) { long s = 0; foreach (var c in _utxos.Values) s += c.value; return s; } }
    /// <summary>The stored proof for a coin — handed to the next payee when this coin is spent.</summary>
    public SpvEnvelope? ProofFor(string outpoint) { lock (_lock) return _proofs.TryGetValue(outpoint, out var e) ? e : null; }

    /// <summary>The wallet's spendable coins (for coin selection): txid, vout, value, locking script.</summary>
    public IReadOnlyList<(string txid, int vout, long value, byte[] script)> Utxos()
    {
        lock (_lock)
        {
            var o = new List<(string, int, long, byte[])>();
            foreach (var kv in _utxos)
            {
                int c = kv.Key.LastIndexOf(':');
                o.Add((kv.Key[..c], int.Parse(kv.Key[(c + 1)..]), kv.Value.value, kv.Value.script));
            }
            return o;
        }
    }
    public void Spend(string outpoint) { lock (_lock) { _utxos.Remove(outpoint); _tokens.Remove(outpoint); _proofs.Remove(outpoint); } }
    public int CoinCount { get { lock (_lock) return _utxos.Count; } }

    /// <summary>The wallet's owned TOKEN/NFT coins (carrier-script UTXOs whose P2PKH tail is ours): identity,
    /// deeds, cards — read straight from chain coins, NO side files. (outpoint, value, locking script). Decode
    /// each with OnChainActions.WalletTokens to get its type/face and whether it is the identity token.</summary>
    public IReadOnlyList<(string outpoint, long value, byte[] script)> TokenCoins()
    {
        lock (_lock) { var o = new List<(string, long, byte[])>(); foreach (var kv in _tokens) o.Add((kv.Key, kv.Value.value, kv.Value.script)); return o; }
    }

    /// <summary>Receive an UNCONFIRMED transaction — the raw tx arrived (e.g. handed over with a transfer)
    /// but it has NO merkle proof yet. Credit owned outputs as PENDING: NOT spendable, shown in the
    /// unconfirmed area, and watched until a proof arrives (→ confirmed via Receive) or it is flagged a
    /// double-spend (→ invalid via MarkInvalid). Returns the number of pending coins added.</summary>
    public int ReceivePending(byte[] rawTx)
    {
        var tx = Tx.Parse(rawTx); if (tx is null) return 0;
        string txid = Tx.Txid(tx); int added = 0;
        lock (_lock)
        {
            if (_pending.Count > 100_000) return 0;                            // DoS guard: cap unconfirmed entries
            if (_invalid.ContainsKey(txid)) return 0;                          // already known-bad
            for (int v = 0; v < tx.Outputs.Count; v++)
                if (_owned.Contains(Tx.ToHex(tx.Outputs[v].Script)))
                {
                    string op = txid + ":" + v;
                    if (_utxos.ContainsKey(op)) continue;                      // already confirmed
                    if (_pending.ContainsKey(op)) continue;                    // already pending
                    _pending[op] = (tx.Outputs[v].Value, tx.Outputs[v].Script, rawTx); added++;
                }
        }
        return added;
    }

    /// <summary>Flag a received transaction as a DOUBLE-SPEND / INVALID (its input was already spent, or a
    /// peer/node rejected it). Its coins are removed from pending AND confirmed and recorded with a reason,
    /// so it surfaces in the invalid area and is never spent.</summary>
    public void MarkInvalid(string txid, string reason)
    {
        lock (_lock)
        {
            _invalid[txid] = reason;
            foreach (var op in new List<string>(_pending.Keys)) if (op.StartsWith(txid + ":")) _pending.Remove(op);
            foreach (var op in new List<string>(_utxos.Keys)) if (op.StartsWith(txid + ":")) { _utxos.Remove(op); _proofs.Remove(op); }
        }
    }

    /// <summary>Total credited by UNCONFIRMED received txs (informational; NOT part of spendable Balance).</summary>
    public long PendingBalance() { lock (_lock) { long s = 0; foreach (var c in _pending.Values) s += c.value; return s; } }

    /// <summary>UNCONFIRMED received transactions (txid, credited sats, coin count) — the unconfirmed area.</summary>
    public IReadOnlyList<(string txid, long credited, int coins)> PendingReceived()
    {
        lock (_lock)
        {
            var by = new Dictionary<string, (long v, int n)>();
            foreach (var kv in _pending)
            {
                string t = kv.Key[..kv.Key.LastIndexOf(':')];
                var cur = by.TryGetValue(t, out var e) ? e : (0L, 0);
                by[t] = (cur.Item1 + kv.Value.value, cur.Item2 + 1);
            }
            var o = new List<(string, long, int)>();
            foreach (var kv in by) o.Add((kv.Key, kv.Value.v, kv.Value.n));
            return o;
        }
    }

    /// <summary>DOUBLE-SPEND / INVALID received transactions (txid, reason) — the invalid area.</summary>
    public IReadOnlyList<(string txid, string reason)> InvalidReceived()
    {
        lock (_lock) { var o = new List<(string, string)>(); foreach (var kv in _invalid) o.Add((kv.Key, kv.Value)); return o; }
    }

    /// <summary>Received transactions still held (by txid), with the total credited to this wallet and the
    /// number of coins from that tx — drives the wallet History view.</summary>
    public IReadOnlyList<(string txid, long credited, int coins)> ReceivedHistory()
    {
        lock (_lock)
        {
            var by = new Dictionary<string, (long v, int n)>();
            foreach (var kv in _utxos)
            {
                string t = kv.Key[..kv.Key.LastIndexOf(':')];
                var cur = by.TryGetValue(t, out var e) ? e : (0L, 0);
                by[t] = (cur.Item1 + kv.Value.value, cur.Item2 + 1);
            }
            var o = new List<(string, long, int)>();
            foreach (var kv in by) o.Add((kv.Key, kv.Value.v, kv.Value.n));
            return o;
        }
    }

    /// <summary>Persist the stored envelopes so the next open shows the balance instantly (no re-fetch).
    /// One line per distinct envelope: rawTxHex|header80Hex|branchCsv|index.</summary>
    public void Save(string path)
    {
        lock (_lock)
        {
            var seen = new HashSet<string>();
            var sb = new System.Text.StringBuilder();
            foreach (var e in _proofs.Values)   // CONFIRMED envelopes (4 fields, no tag — back-compatible)
            {
                string key = Tx.ToHex(e.RawTx);
                if (!seen.Add(key)) continue;
                sb.Append(key).Append('|').Append(Tx.ToHex(e.Header80)).Append('|').Append(string.Join(",", e.Branch)).Append('|').Append(e.Index).Append('\n');
            }
            var seenP = new HashSet<string>();
            foreach (var c in _pending.Values)  // UNCONFIRMED (P|rawTxHex)
            {
                string key = Tx.ToHex(c.rawTx);
                if (!seenP.Add(key)) continue;
                sb.Append("P|").Append(key).Append('\n');
            }
            foreach (var kv in _invalid)        // INVALID / double-spend (X|txid|reason)
                sb.Append("X|").Append(kv.Key).Append('|').Append(kv.Value.Replace("\n", " ")).Append('\n');
            System.IO.File.WriteAllText(path, sb.ToString());
        }
    }

    /// <summary>Load persisted envelopes and re-credit (each is re-verified by Receive). Total — bad
    /// lines are skipped.</summary>
    public void Load(string path)
    {
        if (!System.IO.File.Exists(path)) return;
        foreach (var line in System.IO.File.ReadAllLines(path))
        {
            if (line.Length == 0) continue;
            var p = line.Split('|');
            try
            {
                if (p[0] == "P" && p.Length == 2) { ReceivePending(Tx.FromHex(p[1])); continue; }   // UNCONFIRMED
                if (p[0] == "X" && p.Length >= 2) { lock (_lock) _invalid[p[1]] = p.Length > 2 ? p[2] : "invalid"; continue; }  // INVALID
                if (p.Length != 4) continue;
                var branch = p[2].Length == 0 ? new List<string>() : new List<string>(p[2].Split(','));
                Receive(new SpvEnvelope(Tx.FromHex(p[0]), Tx.FromHex(p[1]), branch, long.Parse(p[3])));   // CONFIRMED
            }
            catch { }
        }
    }
}
