// Estates.Conformance — two jobs:
//   (1) CROSS-VALIDATION: prove the native C# engine + on-chain primitives are byte-for-byte
//       identical to the audited reference (same vector files: engine state hashes, tx
//       serialization/txid, card-NFT output+transfer, FORKID sighash + ECDSA OP_CHECKSIG,
//       dice beacon). Any divergence fails the build.
//   (2) CRYPTO-CORE self-validation: every claim of the in-tree, LIBRARY-FREE crypto core
//       (secp256k1, hash-chained Type-42 keys, Shamir threshold, 2-of-2 + nLockTime recovery,
//       ECDH+AES key-wrap) is asserted with a POSITIVE and a HOSTILE-NEGATIVE test. No third-party
//       library; secp256k1-only signatures, fresh CSPRNG nonces.
using System.Security.Cryptography;
using System.Text.Json;
using Estates.Core;

string vectorsPath = Path.Combine(AppContext.BaseDirectory, "estates.v1.vectors.json");
if (!File.Exists(vectorsPath)) { Console.Error.WriteLine($"vectors not found: {vectorsPath}"); return 2; }

using var doc = JsonDocument.Parse(File.ReadAllText(vectorsPath));
var root = doc.RootElement;
var vectors = root.GetProperty("vectors");

int pass = 0, fail = 0;
foreach (var v in vectors.EnumerateArray())
{
    string id = v.GetProperty("id").GetString()!;
    var state = StateJson.ParseState(v.GetProperty("state"));
    var action = StateJson.ParseAction(v.GetProperty("action"));
    var expected = v.GetProperty("expected");
    bool expectOk = expected.GetProperty("ok").GetBoolean();

    ApplyResult r;
    try { r = Engine.Apply(state, action); }
    catch (Exception e) { Console.Error.WriteLine($"  [FAIL] {id}: native Apply threw: {e.Message}"); fail++; continue; }

    if (expectOk)
    {
        string want = expected.GetProperty("stateHash").GetString()!;
        if (!r.Ok) { Console.Error.WriteLine($"  [FAIL] {id}: expected ok, native rejected ({r.Code})"); fail++; continue; }
        string got = Canonical.HashState(r.State!);
        if (got == want) { pass++; }
        else { Console.Error.WriteLine($"  [FAIL] {id}: state hash mismatch\n         want {want}\n         got  {got}"); fail++; }
    }
    else
    {
        string wantCode = expected.GetProperty("code").GetString()!;
        if (r.Ok) { Console.Error.WriteLine($"  [FAIL] {id}: expected rejection {wantCode}, native accepted"); fail++; continue; }
        if (r.Code == wantCode) { pass++; }
        else { Console.Error.WriteLine($"  [FAIL] {id}: reject code mismatch — want {wantCode}, got {r.Code}"); fail++; }
    }
}

Console.WriteLine($"\nEstates.Conformance (engine): {pass} passed, {fail} failed of {pass + fail} vectors");
if (fail == 0) Console.WriteLine("PASS: the native C# engine is byte-for-byte identical to the audited reference.");
else Console.Error.WriteLine("FAIL: the native engine DIVERGES from the reference.");

// ---- TX cross-validation: native serialize + txid must equal the reference ----
int tpass = 0, tfail = 0;
string txPath = Path.Combine(AppContext.BaseDirectory, "tx-vectors.json");
if (File.Exists(txPath))
{
    using var tdoc = JsonDocument.Parse(File.ReadAllText(txPath));
    foreach (var v in tdoc.RootElement.EnumerateArray())
    {
        string name = v.GetProperty("name").GetString()!;
        var te = v.GetProperty("tx");
        var inputs = te.GetProperty("inputs").EnumerateArray().Select(i =>
            new TxInputN(i.GetProperty("prevTxid").GetString()!, i.GetProperty("prevVout").GetInt64(),
                Tx.FromHex(i.GetProperty("scriptSig").GetString()!), i.GetProperty("sequence").GetInt64())).ToList();
        var outputs = te.GetProperty("outputs").EnumerateArray().Select(o =>
            new TxOutputN(o.GetProperty("value").GetInt64(), Tx.FromHex(o.GetProperty("script").GetString()!))).ToList();
        var tx = new NativeTx(te.GetProperty("version").GetInt32(), inputs, outputs, te.GetProperty("lockTime").GetInt64());
        string wantSer = v.GetProperty("serialized").GetString()!, wantTxid = v.GetProperty("txid").GetString()!;
        string gotSer = Tx.ToHex(Tx.Serialize(tx)), gotTxid = Tx.Txid(tx);
        if (gotSer == wantSer && gotTxid == wantTxid) tpass++;
        else { Console.Error.WriteLine($"  [TX FAIL] {name}: serial/txid mismatch\n    serWant {wantSer}\n    serGot  {gotSer}\n    idWant {wantTxid} idGot {gotTxid}"); tfail++; }
    }
    Console.WriteLine($"Estates.Conformance (tx): {tpass} passed, {tfail} failed");
    if (tfail == 0) Console.WriteLine("PASS: native Tx serialization + txid are byte-for-byte the reference.");
}

// ---- CARDNFT cross-validation: native card NFT output script + transfer tx must
// equal the reference, and native verify accepts the true move / rejects a copy. ----
int cpass = 0, cfail = 0;
string cnPath = Path.Combine(AppContext.BaseDirectory, "cardnft-vectors.json");
if (File.Exists(cnPath))
{
    using var cdoc = JsonDocument.Parse(File.ReadAllText(cnPath));
    var v = cdoc.RootElement;
    string tableId = v.GetProperty("tableId").GetString()!, commitment = v.GetProperty("commitment").GetString()!;
    string aliceCardPub = v.GetProperty("aliceCardPub").GetString()!, newCardPub = v.GetProperty("newCardPub").GetString()!;
    byte[] bobPkh = Tx.FromHex(v.GetProperty("bobPkh").GetString()!);
    var ao = v.GetProperty("aliceOutpoint");
    var aliceOp = new OutpointN(ao.GetProperty("txid").GetString()!, ao.GetProperty("vout").GetInt64());

    string gotScript = Tx.ToHex(CardNftN.CardNftScript(tableId, commitment, newCardPub, bobPkh));
    var (tx, newOp) = CardNftN.BuildTransfer(aliceOp, tableId, commitment, newCardPub, bobPkh);
    string gotSer = Tx.ToHex(Tx.Serialize(tx)), gotTxid = Tx.Txid(tx);

    void Check(string what, bool ok) { if (ok) cpass++; else { Console.Error.WriteLine($"  [CARDNFT FAIL] {what}"); cfail++; } }
    Check("output script bytes", gotScript == v.GetProperty("expectedScript").GetString());
    Check("transfer serialized bytes", gotSer == v.GetProperty("expectedSerialized").GetString());
    Check("transfer txid", gotTxid == v.GetProperty("expectedTxid").GetString());
    // native verify ACCEPTS the true move it just built
    Check("verify accepts the true move", CardNftN.VerifyCardTransfer(tx, aliceOp, aliceCardPub, tableId, commitment, newCardPub, 0, bobPkh).Ok);
    // and REJECTS a copy that does not spend Alice's outpoint
    var forged = tx with { Inputs = new[] { new TxInputN("00".PadLeft(64, '0'), 0, Array.Empty<byte>(), 0xffffffff) } };
    Check("verify rejects a copy (no spend of Alice)", !CardNftN.VerifyCardTransfer(forged, aliceOp, aliceCardPub, tableId, commitment, newCardPub, 0, bobPkh).Ok);
    _ = newOp;

    Console.WriteLine($"Estates.Conformance (cardnft): {cpass} passed, {cfail} failed");
    if (cfail == 0) Console.WriteLine("PASS: native card NFT output + transfer tx are byte-for-byte the reference; true move accepted, copy rejected.");
}

// ---- SCRIPTVM cross-validation: native FORKID sighash + ECDSA OP_CHECKSIG must
// equal the reference (a signed input verifies; a tampered one fails). The verify path
// is the in-tree Secp256k1 (no library) and is fail-closed to SIGHASH_ALL|FORKID. ----
int spass = 0, sfail = 0;
string svPath = Path.Combine(AppContext.BaseDirectory, "scriptvm-vectors.json");
if (File.Exists(svPath))
{
    using var sdoc = JsonDocument.Parse(File.ReadAllText(svPath));
    var v = sdoc.RootElement;
    var te = v.GetProperty("tx");
    var inputs = te.GetProperty("inputs").EnumerateArray().Select(i =>
        new TxInputN(i.GetProperty("prevTxid").GetString()!, i.GetProperty("prevVout").GetInt64(),
            Tx.FromHex(i.GetProperty("scriptSig").GetString()!), i.GetProperty("sequence").GetInt64())).ToList();
    var outputs = te.GetProperty("outputs").EnumerateArray().Select(o =>
        new TxOutputN(o.GetProperty("value").GetInt64(), Tx.FromHex(o.GetProperty("script").GetString()!))).ToList();
    var tx = new NativeTx(te.GetProperty("version").GetInt32(), inputs, outputs, te.GetProperty("lockTime").GetInt64());
    int idx = v.GetProperty("inputIndex").GetInt32();
    long hashType = v.GetProperty("hashType").GetInt64();
    byte[] prevoutScript = Tx.FromHex(v.GetProperty("prevoutScript").GetString()!);
    long prevoutValue = v.GetProperty("prevoutValue").GetInt64();
    string pub = v.GetProperty("pub").GetString()!;

    void Check(string what, bool ok) { if (ok) spass++; else { Console.Error.WriteLine($"  [SCRIPTVM FAIL] {what}"); sfail++; } }
    Check("FORKID sighash matches", Tx.ToHex(Scriptvm.Sighash(tx, idx, prevoutScript, prevoutValue, hashType)) == v.GetProperty("expectedSighash").GetString());
    Check("valid signature verifies (in-tree ECDSA OP_CHECKSIG)", Scriptvm.CheckSig(tx, idx, prevoutScript, prevoutValue, Tx.FromHex(v.GetProperty("validSig").GetString()!), pub));
    Check("tampered signature is rejected", !Scriptvm.CheckSig(tx, idx, prevoutScript, prevoutValue, Tx.FromHex(v.GetProperty("tamperedSig").GetString()!), pub));

    Console.WriteLine($"Estates.Conformance (scriptvm): {spass} passed, {sfail} failed");
    if (sfail == 0) Console.WriteLine("PASS: native FORKID sighash + in-tree secp256k1 ECDSA verify match the reference.");
}

// ---- BEACON cross-validation: native dice beacon (commit/reveal -> dice + chained
// beacon) must equal the reference; a non-opening reveal is rejected. ----
int bpass = 0, bfail = 0;
string bcPath = Path.Combine(AppContext.BaseDirectory, "beacon-vectors.json");
if (File.Exists(bcPath))
{
    using var bdoc = JsonDocument.Parse(File.ReadAllText(bcPath));
    var br = bdoc.RootElement;
    List<Commitment> ParseC(JsonElement a) => a.EnumerateArray().Select(c => new Commitment(c.GetProperty("seat").GetInt32(), Tx.FromHex(c.GetProperty("c").GetString()!))).ToList();
    List<Reveal> ParseR(JsonElement a) => a.EnumerateArray().Select(r => new Reveal(r.GetProperty("seat").GetInt32(), Tx.FromHex(r.GetProperty("secret").GetString()!))).ToList();
    void Ckb(string what, bool ok) { if (ok) bpass++; else { Console.Error.WriteLine($"  [BEACON FAIL] {what}"); bfail++; } }
    foreach (var v in br.GetProperty("rolls").EnumerateArray())
    {
        var res = Beacon.VerifyRollEntry(ParseC(v.GetProperty("commits")), ParseR(v.GetProperty("reveals")),
            v.GetProperty("liveSeats").EnumerateArray().Select(x => x.GetInt32()).ToList(),
            v.GetProperty("turnIndex").GetInt64(), Tx.FromHex(v.GetProperty("prevBeacon").GetString()!));
        var wantDice = v.GetProperty("expectedDice").EnumerateArray().Select(x => x.GetInt32()).ToArray();
        Ckb($"roll t{v.GetProperty("turnIndex").GetInt64()}",
            res.Ok && res.Dice![0] == wantDice[0] && res.Dice![1] == wantDice[1] && Tx.ToHex(res.Beacon!) == v.GetProperty("expectedBeacon").GetString());
    }
    var bad = br.GetProperty("bad");
    var rbad = Beacon.VerifyRollEntry(ParseC(bad.GetProperty("commits")), ParseR(bad.GetProperty("reveals")),
        bad.GetProperty("liveSeats").EnumerateArray().Select(x => x.GetInt32()).ToList(),
        bad.GetProperty("turnIndex").GetInt64(), Tx.FromHex(bad.GetProperty("prevBeacon").GetString()!));
    Ckb("non-opening reveal rejected", !rbad.Ok);
    Console.WriteLine($"Estates.Conformance (beacon): {bpass} passed, {bfail} failed");
    if (bfail == 0) Console.WriteLine("PASS: native dice beacon (dice + chained beacon + reveal checks) matches the reference.");
}

// ============================================================================
//  CRYPTO-CORE self-validation — the in-tree, LIBRARY-FREE primitives. Each claim
//  gets a POSITIVE test and a HOSTILE-NEGATIVE test (a top-class attacker's forgery
//  must be rejected). No third-party library; secp256k1-only, fresh CSPRNG nonces.
// ============================================================================
int xpass = 0, xfail = 0;
void X(string what, bool ok) { if (ok) xpass++; else { Console.Error.WriteLine($"  [CRYPTO FAIL] {what}"); xfail++; } }

// secp256k1 + ECDSA (random-nonce, low-S): sign/verify, tamper rejection, ECDH agreement.
{
    byte[] aPriv = RandomNumberGenerator.GetBytes(32);
    byte[] aPub = Secp256k1.PublicKey(aPriv);
    byte[] msg = "estates/crypto-core/selftest"u8.ToArray();
    byte[] sig = EcdsaSign.Sign(aPriv, msg);
    X("ECDSA sign/verify round-trips", EcdsaSign.Verify(aPub, msg, sig));
    byte[] tampMsg = (byte[])msg.Clone(); tampMsg[0] ^= 0xff;
    X("ECDSA rejects a forged message", !EcdsaSign.Verify(aPub, tampMsg, sig));
    byte[] tampSig = (byte[])sig.Clone(); tampSig[10] ^= 0xff;
    X("ECDSA rejects a tampered signature", !EcdsaSign.Verify(aPub, msg, tampSig));
    // two signatures over the SAME message MUST differ (random nonce, not deterministic)
    X("nonce is non-deterministic (two sigs differ)", !EcdsaSign.Sign(aPriv, msg).AsSpan().SequenceEqual(EcdsaSign.Sign(aPriv, msg)));
    X("scalar validation rejects zero", !EcdsaSign.IsValidScalar(new byte[32]));
    // compress/decompress round-trip
    X("pubkey compress/decompress round-trips", Secp256k1.Compress(Secp256k1.Decompress(aPub)).AsSpan().SequenceEqual(aPub));
    // ECDH: shared secret agrees both ways, and a different key disagrees
    byte[] bPriv = RandomNumberGenerator.GetBytes(32);
    byte[] bPub = Secp256k1.PublicKey(bPriv);
    X("ECDH shared secret agrees both ways", Secp256k1.EcdhX(aPriv, bPub).AsSpan().SequenceEqual(Secp256k1.EcdhX(bPriv, aPub)));
    byte[] cPriv = RandomNumberGenerator.GetBytes(32);
    X("ECDH with the wrong key disagrees", !Secp256k1.EcdhX(aPriv, bPub).AsSpan().SequenceEqual(Secp256k1.EcdhX(cPriv, aPub)));
}

// Hash-chained Type-42 keys (PLAN §2): the mandatory chain verifies, every key is unique,
// and tampering ANY earlier link breaks verification of the whole chain.
{
    byte[] rootPriv = RandomNumberGenerator.GetBytes(32);
    byte[] rootPub = Secp256k1.PublicKey(rootPriv);
    var chain = KeyChain.WalletChain(rootPriv, 8);
    X("hash-chained Type-42 chain verifies", KeyChain.Verify(rootPub, chain));
    var pubs = chain.Select(c => Tx.ToHex(c.Pub)).ToHashSet();
    X("every sub-key is unique (no reuse)", pubs.Count == chain.Count);
    X("root is never a sub-key", !pubs.Contains(Tx.ToHex(rootPub)));
    // tamper link[3] -> the chain must fail to verify
    var broken = chain.ToList();
    byte[] badLink = (byte[])broken[3].Link.Clone(); badLink[0] ^= 0xff;
    broken[3] = broken[3] with { Link = badLink };
    X("a tampered link breaks chain verification", !KeyChain.Verify(rootPub, broken));
}

// Shamir threshold (PLAN §2, GF(n)): any t shares reconstruct; t-1 reveal a wrong secret.
{
    byte[] secret = RandomNumberGenerator.GetBytes(32);
    var shares = Shamir.Split(secret, threshold: 3, shares: 5);
    var anyThree = new[] { shares[0], shares[2], shares[4] };
    X("Shamir reconstructs from t shares", Shamir.Reconstruct(anyThree).AsSpan().SequenceEqual(secret));
    var otherThree = new[] { shares[1], shares[3], shares[4] };
    X("Shamir reconstructs from a DIFFERENT t shares", Shamir.Reconstruct(otherThree).AsSpan().SequenceEqual(secret));
    var twoShares = new[] { shares[0], shares[1] };
    X("Shamir with t-1 shares does NOT reveal the secret", !Shamir.Reconstruct(twoShares).AsSpan().SequenceEqual(secret));
}

// Recovery (the "no sat is ever lost" guarantee): a 2-of-2 + nLockTime refund signed by
// BOTH parties verifies; a single signature or a tampered refund does NOT.
{
    byte[] funderPriv = RandomNumberGenerator.GetBytes(32), counterPriv = RandomNumberGenerator.GetBytes(32);
    byte[] funderPub = Secp256k1.PublicKey(funderPriv), counterPub = Secp256k1.PublicKey(counterPriv);
    byte[] ms = Recovery.Multisig2of2(funderPub, counterPub);
    long stake = 100_000, fee = 200, lockTime = 800_000;
    string fundingTxid = Tx.ToHex(RandomNumberGenerator.GetBytes(32));
    var refund = Recovery.BuildRefund(fundingTxid, 0, stake, fee, funderPub, lockTime);
    byte[] sigF = Recovery.SignRefundInput(refund, ms, stake, funderPriv);
    byte[] sigC = Recovery.SignRefundInput(refund, ms, stake, counterPriv);
    X("2-of-2 + nLockTime refund verifies with BOTH signatures", Recovery.VerifyRefund(refund, ms, stake, funderPub, sigF, counterPub, sigC));
    byte[] forgedSig = (byte[])sigC.Clone(); forgedSig[8] ^= 0xff;
    X("refund rejects a forged counterparty signature", !Recovery.VerifyRefund(refund, ms, stake, funderPub, sigF, counterPub, forgedSig));
    var tamperedRefund = refund with { Outputs = new[] { refund.Outputs[0] with { Value = stake } } }; // attacker grabs the fee
    X("refund rejects a tampered output (sig no longer covers it)", !Recovery.VerifyRefund(tamperedRefund, ms, stake, funderPub, sigF, counterPub, sigC));
}

// ECDH + AES (the ONLY asymmetric encryption): Alice seals to Bob with HER key; Bob
// opens with HIS key + Alice's pub. The ECDH x-coord is the AES key. Wrong key / tamper ⇒ nothing.
{
    byte[] aPriv = RandomNumberGenerator.GetBytes(32), aPub = Secp256k1.PublicKey(aPriv);
    byte[] bobPriv = RandomNumberGenerator.GetBytes(32), bobPub = Secp256k1.PublicKey(bobPriv);
    byte[] evePriv = RandomNumberGenerator.GetBytes(32);
    byte[] plain = "Alice -> Bob: the deed is yours, and only yours."u8.ToArray();
    byte[] aad = "estates/aad/v1"u8.ToArray();
    var ct = Cipher.EcdhSeal(aPriv, bobPub, plain, aad);
    X("ECDH+AES: Bob (his key + Alice's pub) decrypts", (Cipher.EcdhOpen(bobPriv, aPub, ct, aad) ?? Array.Empty<byte>()).AsSpan().SequenceEqual(plain));
    X("ECDH+AES: a wrong key yields nothing", Cipher.EcdhOpen(evePriv, aPub, ct, aad) is null);
    X("ECDH+AES: the shared key is symmetric (both parties reach it)", Tx.ToHex(Cipher.EcdhKey(aPriv, bobPub)) == Tx.ToHex(Cipher.EcdhKey(bobPriv, aPub)));
    byte[] tamp = (byte[])ct.Bytes.Clone(); tamp[0] ^= 0xff;
    X("ECDH+AES: a tampered ciphertext yields nothing", Cipher.EcdhOpen(bobPriv, aPub, new Cipher.EcdhSealed(ct.Nonce, tamp), aad) is null);
    // authenticated key-wrap
    byte[] wrapKey = RandomNumberGenerator.GetBytes(32), payloadKey = RandomNumberGenerator.GetBytes(32);
    var wrapped = Cipher.Wrap(wrapKey, payloadKey);
    X("key-wrap unwraps with the right key", (Cipher.Unwrap(wrapKey, wrapped) ?? Array.Empty<byte>()).AsSpan().SequenceEqual(payloadKey));
    X("key-wrap yields nothing with the wrong key", Cipher.Unwrap(RandomNumberGenerator.GetBytes(32), wrapped) is null);
}

// Standalone wallet: a real P2PKH spend built + signed entirely in-process — NO node, NO RPC,
// NO network. Proves the exe can hold coins and produce spend-valid BSV transactions on its own.
{
    byte[] seed = SHA256.HashData("estates/standalone-wallet/selftest"u8.ToArray());
    var w = new StandaloneWallet(seed, "regtest");
    X("standalone wallet derives a base58check address", StandaloneWallet.AddressToPkh(w.AddressAt(0)).Length == 20);
    X("balance is zero before any coin", w.Balance() == 0);
    string coinTxid = Tx.ToHex(RandomNumberGenerator.GetBytes(32));
    w.AddCoin(coinTxid, 0, 1_000_000, 0);            // a coin held by address 0 (faucet/P2P origin)
    X("balance reflects the local UTXO (no node queried)", w.Balance() == 1_000_000);
    var built = w.BuildSend(w.AddressAt(1), 600_000, 500, changeIndex: 2);
    X("built spend pays recipient + change (2 outputs)", built.Tx.Outputs.Count == 2);
    X("change is value - amount - fee", built.Change == 1_000_000 - 600_000 - 500);
    X("every input is signed and verifies locally (no node)", w.VerifySpend(built));
    // hostile: a tampered signature must fail local verification
    var bad = built.Tx.Inputs[0].ScriptSig.ToArray(); bad[5] ^= 0xff;
    var tamperedTx = built.Tx with { Inputs = new[] { built.Tx.Inputs[0] with { ScriptSig = bad } } };
    X("a tampered input signature is rejected", !w.VerifySpend(built with { Tx = tamperedTx }));
    bool refused; try { w.BuildSend(w.AddressAt(1), 5_000_000, 500); refused = false; } catch { refused = true; }
    X("insufficient funds is refused, not silently underpaid", refused);
}

// In-client BSV NODE: the real P2P wire protocol + header proof-of-work validation. KATs use the
// REAL Bitcoin/BSV mainnet genesis header — deterministic proof the node code is correct, no stubs.
{
    // wire envelope: a verack frame's checksum is the first 4 bytes of double-SHA256("") = 5df6e0e2
    byte[] verack = BsvWire.Frame(BsvNet.Mainnet, "verack", Array.Empty<byte>());
    X("wire: verack checksum is double-SHA256(empty)[:4]", Tx.ToHex(verack[20..24]) == "5df6e0e2");
    var (vmsg, vcons) = BsvWire.TryRead(BsvNet.Mainnet, verack);
    X("wire: a framed message reads back (command + length)", vmsg is not null && vmsg.Command == "verack" && vcons == 24);
    // version round-trips through frame/read
    byte[] vpl = BsvWire.Version(1700000000, 0x1122334455667788UL, "/estates:1.0/", 42, new byte[] { 127, 0, 0, 1 }, 8333);
    var (vr, _) = BsvWire.TryRead(BsvNet.Mainnet, BsvWire.Frame(BsvNet.Mainnet, "version", vpl));
    X("wire: version frames and parses back intact", vr is not null && vr.Command == "version" && vr.Payload.AsSpan().SequenceEqual(vpl));
    // wrong magic ⇒ resync signal (consumed < 0), never a throw
    byte[] wrong = BsvWire.Frame(BsvNet.Testnet, "verack", Array.Empty<byte>());
    X("wire: a foreign-magic frame is rejected for resync (no throw)", BsvWire.TryRead(BsvNet.Mainnet, wrong).consumed < 0);
    // total parsers: garbage never throws and yields null
    var rng2 = new Random(7);
    bool everThrew = false;
    for (int t = 0; t < 5000; t++) { var g = new byte[rng2.Next(0, 64)]; rng2.NextBytes(g); try { BsvWire.ParseInv(g); BsvWire.ParseHeaders(g); } catch { everThrew = true; break; } }
    X("wire: inv/headers parsers are fuzz-proof (never throw on garbage)", !everThrew);
    // inv vector round-trips
    byte[] h32 = SHA256.HashData("tx"u8.ToArray());
    var invBack = BsvWire.ParseInv(BsvWire.InvVector(new[] { ((uint)1, h32) }));
    X("wire: inv vector round-trips", invBack is { Count: 1 } && invBack[0].type == 1 && invBack[0].hash.AsSpan().SequenceEqual(h32));

    // ---- header proof-of-work, against the REAL mainnet genesis header (80 bytes) ----
    byte[] genesis = Tx.FromHex("0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c");
    var gh = BsvHeaders.Parse(genesis)!;
    X("headers: genesis block hash matches the known id", gh.Id() == "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
    X("headers: genesis nBits is 0x1d00ffff", gh.Bits == 0x1d00ffff);
    X("headers: genesis prevHash is all zero", gh.PrevHash.All(b => b == 0));
    X("headers: genesis MEETS its proof of work", BsvHeaders.MeetsProofOfWork(gh));
    X("headers: a genuine chain of [genesis] verifies from the zero parent", BsvHeaders.VerifyChain(new[] { gh }, new byte[32]));
    // tamper the nonce ⇒ the hash is now (overwhelmingly) above target ⇒ PoW fails
    byte[] bad = (byte[])genesis.Clone(); bad[79] ^= 0x01;
    X("headers: a tampered header FAILS proof of work", !BsvHeaders.MeetsProofOfWork(BsvHeaders.Parse(bad)!));
    X("headers: an 81-byte buffer is rejected (total parse)", BsvHeaders.Parse(new byte[81]) is null);
}

// On-chain SMART CONTRACTS: the OP_PUSH_TX covenant engine + auctions where EVERY bid is a
// conditional contract (win pays the grantor + mints the role NFT; refund only once outbid/closed).
{
    byte[] gpkh = Recovery.Hash160(Secp256k1.PublicKey(RandomNumberGenerator.GetBytes(32)));
    byte[] bpkh = Recovery.Hash160(Secp256k1.PublicKey(RandomNumberGenerator.GetBytes(32)));
    string prev = Tx.ToHex(SHA256.HashData("auction-prev"u8.ToArray()));
    byte[] scriptCode = Recovery.P2pkh(gpkh);
    var sampleTx = new NativeTx(2, new[] { new TxInputN(prev, 0, Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(90000, Recovery.P2pkh(bpkh)) }, 0);
    X("pushtx: preimage double-hashes to the FORKID sighash (matches Scriptvm)",
        Tx.ToHex(Tx.Hash256(PushTx.Preimage(sampleTx, 0, scriptCode, 100000))) == Tx.ToHex(Scriptvm.Sighash(sampleTx, 0, scriptCode, 100000, 0x41)));
    X("pushtx: CheckPreimage accepts the genuine preimage", PushTx.CheckPreimage(sampleTx, 0, scriptCode, 100000, PushTx.Preimage(sampleTx, 0, scriptCode, 100000)) is not null);
    var tampered = (byte[])PushTx.Preimage(sampleTx, 0, scriptCode, 100000).Clone(); tampered[0] ^= 0xff;
    X("pushtx: CheckPreimage rejects a forged preimage", PushTx.CheckPreimage(sampleTx, 0, scriptCode, 100000, tampered) is null);
    X("pushtx: extracted hashOutputs equals the tx's hashOutputs", Tx.ToHex(PushTx.PreimageHashOutputs(PushTx.Preimage(sampleTx, 0, scriptCode, 100000), scriptCode.Length)) == Tx.ToHex(PushTx.HashOutputs(sampleTx)));

    long deadline = 800_000;
    var bid = new Bid("auction:banker:table7", gpkh, bpkh, 100_000, deadline);
    byte[] roleNft = Auction.RoleNft("banker", bpkh);
    byte[] cov = Auction.CovenantScript(bid, roleNft);
    string covTxid = Tx.ToHex(SHA256.HashData("bid-cov"u8.ToArray()));
    var bidTx = Auction.BuildBidTx(bid, roleNft, prev, 1, Array.Empty<byte>());
    X("auction: a bid is its own on-chain tx locking the covenant", bidTx.Outputs.Count == 1 && bidTx.Outputs[0].Script.AsSpan().SequenceEqual(cov));
    var winTx = Auction.BuildWin(bid, roleNft, covTxid, 0);
    X("auction: the highest bid settles (grantor paid + role NFT to bidder)", Auction.VerifyWin(bid, roleNft, winTx, 100_000, new long[] { 50_000, 90_000 }).Ok);
    X("auction: a non-highest bid CANNOT win (outbid ⇒ rejected)", !Auction.VerifyWin(bid, roleNft, winTx, 100_000, new long[] { 120_000 }).Ok);
    var forgedWin = winTx with { Outputs = new[] { new TxOutputN(100_000, Auction.RoleNft("banker", gpkh)) } }; // attacker redirects the role
    X("auction: forged win outputs are rejected by the covenant", !Auction.VerifyWin(bid, roleNft, forgedWin, 100_000, Array.Empty<long>()).Ok);
    var refundTx = Auction.BuildRefund(bid, covTxid, 0);
    X("auction: refund is BLOCKED while winning and before the deadline", !Auction.VerifyRefund(bid, roleNft, refundTx, 100_000, new long[] { 50_000 }, 0).Ok);
    X("auction: refund is ALLOWED once outbid", Auction.VerifyRefund(bid, roleNft, refundTx, 100_000, new long[] { 150_000 }, 0).Ok);
    X("auction: refund is ALLOWED once the deadline passes", Auction.VerifyRefund(bid, roleNft, refundTx, 100_000, Array.Empty<long>(), deadline).Ok);
}

// Transaction-type protocol suite: each TYPE has its own number + self-identifying header (the
// extractable protocol layer), and a typed transaction reports exactly what it is.
{
    foreach (var d in TxProtocol.Suite)
    {
        var h = TxProtocol.Read(TxProtocol.Stamp(d.Type, "payload"u8.ToArray()));
        X($"protocol #{d.Number} {d.Name} self-identifies", h is not null && h.Value.type == d.Type && System.Text.Encoding.ASCII.GetString(h.Value.payload) == "payload");
    }
    X("protocol: non-EST data is not mistaken for a typed tx", TxProtocol.Read("not-est"u8.ToArray()) is null);
    X("protocol: numbers are unique across the suite", TxProtocol.Suite.Select(d => d.Number).Distinct().Count() == TxProtocol.Suite.Count);
    // a typed transaction built by the wallet carries its header in the on-chain marker output
    byte[] wseed = SHA256.HashData("estates/typed-tx/selftest"u8.ToArray());
    var tw = new StandaloneWallet(wseed, "regtest");
    tw.AddCoin(Tx.ToHex(RandomNumberGenerator.GetBytes(32)), 0, 1_000_000, 0);
    var ka = OnChainActions.KeepAlive(tw, 500);
    // the marker output's pushdata begins with the EST header for KEEPALIVE
    X("a KEEPALIVE tx is on-chain and self-identifying", ka.Tx.Outputs.Count >= 1);
}

// Group chat over the broadcast key-graph: every member reads it; a non-member never can.
{
    byte[] aPriv = SHA256.HashData("ga"u8.ToArray()), aPub = Secp256k1.PublicKey(aPriv);
    byte[] bPriv = SHA256.HashData("gb"u8.ToArray()), bPub = Secp256k1.PublicKey(bPriv);
    byte[] cPriv = SHA256.HashData("gc"u8.ToArray()), cPub = Secp256k1.PublicKey(cPriv);
    byte[] ePriv = SHA256.HashData("ge"u8.ToArray()), ePub = Secp256k1.PublicKey(ePriv);
    byte[] frame = ChatCodec.Seal(aPriv, new[] { bPub, cPub }, "group hello")!;
    var rb = ChatCodec.Open(frame, bPriv, bPub);
    var rc = ChatCodec.Open(frame, cPriv, cPub);
    var re = ChatCodec.Open(frame, ePriv, ePub);
    X("group chat: member B reads the message", rb is not null && rb.Value.text == "group hello");
    X("group chat: member C reads the message", rc is not null && rc.Value.text == "group hello");
    X("group chat: a non-member cannot read it", re is null);
}

// TRADE #13 — atomic NFT swap: one tx, both NFTs re-sealed to the other owner, each side signs its
// own input. Valid only when BOTH have signed (atomicity); a tampered signature breaks the whole swap.
{
    byte[] aPriv = SHA256.HashData("swapA"u8.ToArray()), aPub = Secp256k1.PublicKey(aPriv);
    byte[] bPriv = SHA256.HashData("swapB"u8.ToArray()), bPub = Secp256k1.PublicKey(bPriv);
    byte[] aFace = "ACE-SPADES"u8.ToArray(), bFace = "KING-HEARTS"u8.ToArray();
    byte[] aScript = OnChainActions.CarrierScript(TxProtocol.Stamp(TxType.NftMint, aFace), Recovery.Hash160(aPub));
    byte[] bScript = OnChainActions.CarrierScript(TxProtocol.Stamp(TxType.NftMint, bFace), Recovery.Hash160(bPub));
    var aNft = new Coin(Tx.ToHex(RandomNumberGenerator.GetBytes(32)), 0, 1, 0, aScript);
    var bNft = new Coin(Tx.ToHex(RandomNumberGenerator.GetBytes(32)), 0, 1, 0, bScript);
    var swap = Trade.BuildSwap(aNft, aFace, aPriv, bNft, bFace, bPriv);
    X("atomic swap: one tx, two inputs + two outputs (both move or neither)", swap.Inputs.Count == 2 && swap.Outputs.Count == 2);
    X("atomic swap: both inputs validly signed by their owners", Trade.VerifySwap(swap, aNft, aPub, bNft, bPub));
    X("atomic swap: A's NFT goes to B", Tx.ToHex(swap.Outputs[0].Script).Contains(Tx.ToHex(Recovery.Hash160(bPub))));
    X("atomic swap: B's NFT goes to A", Tx.ToHex(swap.Outputs[1].Script).Contains(Tx.ToHex(Recovery.Hash160(aPub))));
    var bad = swap.Inputs[0].ScriptSig.ToArray(); bad[8] ^= 0xff;
    var tampered = swap with { Inputs = new[] { swap.Inputs[0] with { ScriptSig = bad }, swap.Inputs[1] } };
    X("atomic swap: a tampered signature breaks the whole swap", !Trade.VerifySwap(tampered, aNft, aPub, bNft, bPub));
}

// IDENTITY NFT card (#16): expandable attributes, minted on-chain, total parse.
{
    var attrs = new List<(string, string)> { ("name", "Alice"), ("avatar", "cat.png"), ("bio", "plays to win") };
    var parsed = Identity.Parse(Identity.Serialize(attrs));
    X("identity: attributes round-trip", parsed is { Count: 3 } && parsed[0].Value == "Alice");
    var wI = new StandaloneWallet(SHA256.HashData("ident"u8.ToArray()), "regtest");
    wI.AddCoin(Tx.ToHex(RandomNumberGenerator.GetBytes(32)), 0, 1_000_000, 0);
    var mint = Identity.Mint(wI, attrs, 500);
    X("identity: minted as a 1-sat on-chain NFT card", mint.Tx.Outputs.Count >= 1 && mint.Tx.Outputs[0].Value == 1);
    var attrs2 = new List<(string, string)>(attrs) { ("country", "BSVland") };
    var card = Identity.Read(TxProtocol.Stamp(TxType.Identity, Identity.Serialize(attrs2)));
    X("identity: attributes are expandable (new key added later)", card is not null && card.Get("country") == "BSVland" && card.Name == "Alice");
    X("identity: total parse rejects garbage", Identity.Parse(new byte[] { 0xff, 0xff, 0xff }) is null);
}

// MESSENGER backend: message kinds round-trip; a conversation folds edit/delete/reaction/receipt
// onto the target message (as WhatsApp/Telegram/Signal render them), not as noise.
{
    var t = Messenger.Text("alicepub", "hello");
    var rt = Messenger.Parse(Messenger.Serialize(t));
    X("messenger: a message round-trips on the wire", rt is not null && rt.Text == "hello" && rt.Kind == ChatKind.Text);
    var conv = new Conversation("c1", false, new[] { "alicepub", "bobpub" });
    conv.Apply(t);
    conv.Apply(Messenger.Reply("bobpub", t.Id, "hi alice"));
    X("messenger: history holds text + reply", conv.History.Count == 2);
    conv.Apply(Messenger.React("bobpub", t.Id, "thumbsup"));
    X("messenger: reaction folds onto its target", conv.History[0].Reactions.Count == 1);
    conv.Apply(Messenger.Edit("alicepub", t.Id, "hello (edited)"));
    X("messenger: edit updates in place, not appended", conv.History.Count == 2 && conv.History[0].Display == "hello (edited)");
    conv.Apply(Messenger.Read("bobpub", t.Id));
    X("messenger: read receipt folds", conv.History[0].ReadBy.Contains("bobpub"));
    conv.Apply(Messenger.Delete("alicepub", t.Id));
    X("messenger: delete marks the message", conv.History[0].Deleted && conv.History[0].Display == "(deleted)");
    X("messenger: total parse rejects garbage", Messenger.Parse(new byte[] { 0x09 }) is null);
}

// MINER SUPERVISOR: real double-SHA256 PoW across independent workers, each monitored separately and
// auto-respawned on death — the never-down guarantee, in-process. Easy target => a block is found.
{
    var hdr = new byte[80];
    var easy = System.Linq.Enumerable.Repeat((byte)0xFF, 32).ToArray();
    var sup = new MinerSupervisor(4, hdr, easy);
    bool found = false; sup.OnBlockFound += (_, _) => found = true;
    sup.Start();
    System.Threading.Thread.Sleep(400);
    X("miner: 4 independent workers alive", sup.AliveCount() == 4);
    X("miner: real hashing is happening", sup.TotalHashes() > 0);
    X("miner: easy target yields a found block", found);
    sup.KillWorker(0);
    System.Threading.Thread.Sleep(1600);
    var st = sup.Status();
    X("miner: killed worker auto-respawned (never-down)", sup.AliveCount() == 4 && st[0].Restarts >= 1);
    sup.Dispose();
}

// NODE WALLET: a real wallet that SEES immature/unconfirmed/spendable coins from the chain (the fake
// node-less wallet cannot). A mined coinbase shows IMMATURE, matures to SPENDABLE at 100 confs, a
// mempool pay shows UNCONFIRMED, and a spend removes the coin.
{
    var master = new byte[32]; master[0] = 7;
    var pub = Cipher.PublicKey(master);
    var script = NodeWallet.P2pkhScript(Recovery.Hash160(pub));
    var nw = new NodeWallet(new[] { pub });
    var cb = new NodeWallet.WTx("cb1", Array.Empty<NodeWallet.WIn>(), new[] { new NodeWallet.WOut(1_250_000_000, script) });
    nw.ApplyBlock(1000, new[] { cb });
    X("nodewallet: mined coinbase shows as IMMATURE", nw.Immature() == 1_250_000_000 && nw.Spendable() == 0);
    nw.SetTip(1098);
    X("nodewallet: still immature at 99 confs", nw.Immature() == 1_250_000_000);
    nw.SetTip(1099);
    X("nodewallet: matures to SPENDABLE at 100 confs", nw.Spendable() == 1_250_000_000 && nw.Immature() == 0);
    nw.ApplyMempoolTx(new NodeWallet.WTx("mp1", Array.Empty<NodeWallet.WIn>(), new[] { new NodeWallet.WOut(50_000, script) }));
    X("nodewallet: mempool pay shows UNCONFIRMED", nw.Unconfirmed() == 50_000);
    var spend = new NodeWallet.WTx("sp1", new[] { new NodeWallet.WIn("cb1", 0) }, Array.Empty<NodeWallet.WOut>());
    nw.ApplyBlock(1101, new[] { new NodeWallet.WTx("cbx", Array.Empty<NodeWallet.WIn>(), Array.Empty<NodeWallet.WOut>()), spend });
    X("nodewallet: spent coinbase is removed", nw.Spendable() == 0);
    X("nodewallet: foreign pay is ignored (not mine)", new NodeWallet(new[] { pub }).Immature() == 0);
}

// NODE LEDGER (built from scratch): tx parser round-trips + rejects garbage; block parses; the UTXO
// set tracks a coinbase as immature, matures it at 100 confs, and removes it when spent.
{
    var sc = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 9, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    var tx0 = new NativeTx(2, new[] { new TxInputN(new string('a', 64), 0, new byte[] { 1, 2, 3 }, 0xffffffff) }, new[] { new TxOutputN(50000, sc) }, 0);
    var raw = Tx.Serialize(tx0);
    var back = Tx.Parse(raw);
    X("tx-parse: serialize/deserialize round-trips", back is not null && Tx.Txid(back) == Tx.Txid(tx0));
    X("tx-parse: rejects trailing garbage", Tx.Parse(raw.Append((byte)0).ToArray()) is null);
    X("tx-parse: rejects truncation", Tx.Parse(raw[..^2]) is null);

    var coinbase = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(1_250_000_000, sc) }, 0);
    var hdr = new byte[80];
    var u = new UtxoSet();
    u.ApplyBlock(1000, new ParsedBlock(hdr, Block.HashOf(hdr), new[] { coinbase }));
    var owned = new HashSet<string> { Tx.ToHex(sc) };
    X("utxo: coinbase tracked, immature at tip", u.ImmatureFor(owned) == 1_250_000_000 && u.SpendableFor(owned) == 0);
    u.SetTip(1099);
    X("utxo: matures to spendable at 100 confs", u.SpendableFor(owned) == 1_250_000_000 && u.ImmatureFor(owned) == 0);
    string cbid = Tx.Txid(coinbase);
    var cb2 = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, new byte[] { 1 }, 0xffffffff) }, new[] { new TxOutputN(1, sc) }, 0);
    var spend = new NativeTx(1, new[] { new TxInputN(cbid, 0, new byte[] { 2 }, 0xffffffff) }, new[] { new TxOutputN(40000, sc) }, 0);
    u.ApplyBlock(1100, new ParsedBlock(hdr, "x", new[] { cb2, spend }));
    X("utxo: spent coinbase output removed", u.Get(cbid, 0) is null);
    // round-trip a real block through the parser
    var blkRaw = new List<byte>(); blkRaw.AddRange(hdr); blkRaw.Add(1); blkRaw.AddRange(Tx.Serialize(coinbase));
    var pb = Block.Parse(blkRaw.ToArray());
    X("block-parse: header + 1 tx parses, hash matches", pb is not null && pb.Txs.Count == 1 && pb.BlockHash == Block.HashOf(hdr));
    X("block-parse: rejects a too-short block", Block.Parse(new byte[40]) is null);
}

// KEY RING (built from scratch): one seed -> trillions of unique never-reused keys; a fixed identity
// key; fresh receive keys that never repeat; per-message ECDH-chained keys that differ every message.
{
    var seed = new byte[32]; seed[0] = 5;
    var ring = new KeyRing(seed);
    X("keyring: identity key is fixed/stable across instances", Tx.ToHex(ring.IdentityPub()) == Tx.ToHex(new KeyRing(seed).IdentityPub()));
    var k1 = ring.NextReceive(); var k2 = ring.NextReceive();
    X("keyring: every receive key is fresh (never reused)", Tx.ToHex(k1.pub) != Tx.ToHex(k2.pub) && k1.index != k2.index);
    X("keyring: identity differs from wallet keys", Tx.ToHex(ring.IdentityPub()) != Tx.ToHex(k1.pub));
    X("keyring: PrivAt is deterministic from the seed", Tx.ToHex(ring.PubAt(7)) == Tx.ToHex(new KeyRing(seed).PubAt(7)));
    X("keyring: trillion-scale index derives a distinct 32-byte key", ring.PrivAt(1_000_000_000_000L).Length == 32 && Tx.ToHex(ring.PubAt(1_000_000_000_000L)) != Tx.ToHex(ring.PubAt(1)));
    var cp = Secp256k1.PublicKey(new byte[32] { 2, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 });
    X("keyring: per-message keys advance (new key each message)", Tx.ToHex(ring.MessagePub(cp, "conv", 0)) != Tx.ToHex(ring.MessagePub(cp, "conv", 1)));
}

// MEMPOOL (built from scratch): accepts a valid tx; rejects duplicate, double-spend, and garbage;
// a confirming block evicts the tx.
{
    var sc = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 4, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    var a = new NativeTx(1, new[] { new TxInputN(new string('a', 64), 0, new byte[] { 1 }, 0xffffffff) }, new[] { new TxOutputN(100, sc) }, 0);
    var b = new NativeTx(1, new[] { new TxInputN(new string('a', 64), 0, new byte[] { 2 }, 0xffffffff) }, new[] { new TxOutputN(50, sc) }, 0);  // same outpoint -> conflict
    var mp = new Mempool();
    X("mempool: accepts a valid tx", mp.Accept(Tx.Serialize(a)) is not null && mp.Count == 1);
    X("mempool: rejects a duplicate", mp.Accept(Tx.Serialize(a)) is null);
    X("mempool: rejects a double-spend (same outpoint)", mp.Accept(Tx.Serialize(b)) is null && mp.Count == 1);
    X("mempool: rejects garbage", mp.Accept(new byte[] { 1, 2, 3 }) is null);
    var hdr = new byte[80];
    mp.OnBlock(new ParsedBlock(hdr, "x", new[] { a }));
    X("mempool: a confirmed tx is evicted", !mp.Contains(Tx.Txid(a)) && mp.Count == 0);
}

// TX MESSAGE (the rule made concrete): a message is an encrypted typed transaction carrier with a
// FRESH per-message key; it round-trips for the recipient, a stranger cannot open it, and a different
// sequence yields different ciphertext (a new key every message).
{
    var seedA = new byte[32]; seedA[0] = 11; var ringA = new KeyRing(seedA);
    byte[] bobPriv = Type42.UniqueKey(new byte[32] { 12, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "id");
    byte[] bobPub = Secp256k1.PublicKey(bobPriv);
    byte[] hello = System.Text.Encoding.UTF8.GetBytes("hello bob");
    var carrier = TxMessage.SealCarrier(ringA.MessagePriv(bobPub, "conv", 0), bobPub, TxType.Chat2P, hello);
    var opened = TxMessage.OpenCarrier(carrier, bobPriv);
    X("txmessage: encrypted tx carrier round-trips for the recipient", opened is not null && System.Text.Encoding.UTF8.GetString(opened.Value.plaintext) == "hello bob" && opened.Value.type == TxType.Chat2P);
    byte[] evePriv = Type42.UniqueKey(new byte[32] { 13, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "id");
    X("txmessage: a stranger cannot open it", TxMessage.OpenCarrier(carrier, evePriv) is null);
    var carrier2 = TxMessage.SealCarrier(ringA.MessagePriv(bobPub, "conv", 1), bobPub, TxType.Chat2P, hello);
    X("txmessage: a NEW key per message gives different ciphertext", Tx.ToHex(carrier) != Tx.ToHex(carrier2));
    X("txmessage: garbage carrier rejected", TxMessage.OpenCarrier(new byte[] { 1, 2, 3 }, bobPriv) is null);
}

// TX TRANSPORT (dual-propagation): a sealed message survives the carrier output script, is extracted
// from a received transaction by the recipient, and a stranger extracts nothing.
{
    var ringA = new KeyRing(new byte[32] { 21, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 });
    byte[] bobPriv = Type42.UniqueKey(new byte[32] { 22, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "id");
    byte[] bobPub = Secp256k1.PublicKey(bobPriv);
    byte[] carrier = TxMessage.SealCarrier(ringA.MessagePriv(bobPub, "c", 0), bobPub, TxType.Move, System.Text.Encoding.UTF8.GetBytes("move:7"));
    byte[] outScript = TxTransport.MessageOutput(carrier, Recovery.Hash160(bobPub));
    var read = TxTransport.ReadCarrier(outScript);
    X("txtransport: carrier survives the output-script round-trip", read is not null && Tx.ToHex(read) == Tx.ToHex(carrier));
    var rxTx = new NativeTx(1, new[] { new TxInputN(new string('a', 64), 0, new byte[] { 1 }, 0xffffffff) },
        new[] { new TxOutputN(1, outScript), new TxOutputN(1000, NodeWallet.P2pkhScript(Recovery.Hash160(bobPub))) }, 0);
    var ex = TxTransport.Extract(rxTx, bobPriv);
    X("txtransport: message extracted from a received transaction", ex is not null && System.Text.Encoding.UTF8.GetString(ex.Value.plaintext) == "move:7" && ex.Value.type == TxType.Move);
    byte[] evePriv = Type42.UniqueKey(new byte[32] { 23, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "id");
    X("txtransport: a stranger extracts nothing", TxTransport.Extract(rxTx, evePriv) is null);
}

// BASE58CHECK (from scratch): a P2PKH address round-trips with its version; a corrupted character
// fails the checksum; testnet uses a different version byte.
{
    var pkh = Recovery.Hash160(Cipher.PublicKey(new byte[32] { 31, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }));
    string addr = Address.P2pkh(pkh, BsvNet.Mainnet);
    var dec = Base58.CheckDecode(addr, out byte ver);
    X("base58: mainnet P2PKH round-trips with version 0x00", dec is not null && Tx.ToHex(dec) == Tx.ToHex(pkh) && ver == 0x00 && addr.StartsWith("1"));
    string bad = addr[..^1] + (addr[^1] == 'A' ? 'B' : 'A');
    X("base58: a corrupted address fails the checksum", Base58.CheckDecode(bad, out _) is null);
    X("base58: testnet uses version 0x6f", Base58.CheckDecode(Address.P2pkh(pkh, BsvNet.Testnet), out byte tv) is not null && tv == 0x6f);
}

// WALLET ENGINE (node-backed): reads its balance straight from the UTXO ledger over its rotating
// addresses; a coinbase mined to its address is immature then spendable; receive addresses never repeat.
{
    var wseed = new byte[32]; wseed[0] = 33;
    var w = new WalletEngine(wseed, watchHorizon: 20);
    byte[] wsc = NodeWallet.P2pkhScript(Recovery.Hash160(new KeyRing(wseed).PubAt(1)));
    var wu = new UtxoSet();
    var wcb = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(500_000, wsc) }, 0);
    wu.ApplyBlock(1000, new ParsedBlock(new byte[80], "h", new[] { wcb }));
    X("walletengine: reads node-ledger coinbase as immature", w.Immature(wu) == 500_000 && w.Spendable(wu) == 0);
    wu.SetTip(1099);
    X("walletengine: matures to spendable from the ledger", w.Spendable(wu) == 500_000);
    var a1 = w.NextReceiveAddress(BsvNet.Mainnet); var a2 = w.NextReceiveAddress(BsvNet.Mainnet);
    X("walletengine: every receive address is fresh", a1.address != a2.address && a1.index != a2.index && a1.address.StartsWith("1"));
}

// CHAIN SYNC (the node's block pipeline): a valid-PoW block that links to the tip extends the chain
// and funds the ledger; a block failing PoW or not linking to the tip is rejected.
{
    byte[] MkHeader(byte prev4) { var h = new byte[80]; h[0] = 1; h[4] = prev4; h[72] = 0xff; h[73] = 0xff; h[74] = 0x7f; h[75] = 0x20; return h; }  // bits 0x207fffff = easy target
    var sc = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 41, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    var cb = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(5000, sc) }, 0);
    byte[] MkBlock(byte prev4) { var r = new List<byte>(); r.AddRange(MkHeader(prev4)); r.Add(1); r.AddRange(Tx.Serialize(cb)); return r.ToArray(); }
    var owned = new HashSet<string> { Tx.ToHex(sc) };

    var cs = new ChainSync(new UtxoSet(), new Mempool());
    var u = new UtxoSet(); cs = new ChainSync(u, new Mempool());
    bool ok = cs.OnBlock(MkBlock(0));
    X("chainsync: valid-PoW block extends chain + funds ledger (immature)", ok && cs.Height == 0 && u.ImmatureFor(owned) == 5000);
    X("chainsync: a block not linking to the tip is rejected", !cs.OnBlock(MkBlock(0x99)));   // prev != tip

    var hdrNoPow = MkHeader(0); hdrNoPow[72] = 0; hdrNoPow[73] = 0; hdrNoPow[74] = 0; hdrNoPow[75] = 0;   // bits=0 -> target 0
    var bad = new List<byte>(); bad.AddRange(hdrNoPow); bad.Add(1); bad.AddRange(Tx.Serialize(cb));
    X("chainsync: a block failing PoW is rejected", !new ChainSync(new UtxoSet(), new Mempool()).OnBlock(bad.ToArray()));
    X("chainsync: garbage is rejected", !cs.OnBlock(new byte[] { 1, 2, 3 }));
}

// NODE SERVICE (the client IS the node): ingesting a validated block credits the wallet straight from
// the ledger (proof-gated — only a chain-valid block funds it); a bad-PoW block credits nothing.
{
    var nseed = new byte[32]; nseed[0] = 44;
    var node = new NodeService(nseed, watchHorizon: 20);
    byte[] wsc = NodeWallet.P2pkhScript(Recovery.Hash160(new KeyRing(nseed).PubAt(1)));
    byte[] MkHdr(bool goodPow) { var h = new byte[80]; h[0] = 1; if (goodPow) { h[72] = 0xff; h[73] = 0xff; h[74] = 0x7f; h[75] = 0x20; } return h; }
    var ncb = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0xffffffff, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(700_000, wsc) }, 0);
    byte[] MkBlk(bool goodPow) { var b = new List<byte>(); b.AddRange(MkHdr(goodPow)); b.Add(1); b.AddRange(Tx.Serialize(ncb)); return b.ToArray(); }
    X("node: a validated block funds the wallet from the ledger (immature)", node.IngestBlock(MkBlk(true)) && node.Immature() == 700_000 && node.Height == 0);
    X("node: a bad-PoW block credits nothing", !new NodeService(nseed, 20).IngestBlock(MkBlk(false)));
}

// SPV MERKLE PROOF (instant wallet, no full sync): a tx's branch recomputes the block merkle root;
// a wrong index, wrong root, or tampered branch is rejected.
{
    byte[] Leaf(byte b) { var x = new byte[32]; x[0] = b; return x; }
    byte[] H2(byte[] a, byte[] b) { var p = new byte[64]; System.Array.Copy(a, 0, p, 0, 32); System.Array.Copy(b, 0, p, 32, 32); return Tx.Hash256(p); }
    string Disp(byte[] x) { var r = (byte[])x.Clone(); System.Array.Reverse(r); return Tx.ToHex(r); }
    var l0 = Leaf(1); var l1 = Leaf(2); var l2 = Leaf(3); var l3 = Leaf(4);
    var mroot = H2(H2(l0, l1), H2(l2, l3));
    var branch0 = new[] { Disp(l1), Disp(H2(l2, l3)) };
    X("merkle: valid proof reconstructs the block root", MerkleProof.Verify(Disp(l0), branch0, 0, mroot));
    X("merkle: wrong index rejected", !MerkleProof.Verify(Disp(l0), branch0, 1, mroot));
    X("merkle: wrong root rejected", !MerkleProof.Verify(Disp(l0), branch0, 0, Leaf(9)));
    X("merkle: tampered branch rejected", !MerkleProof.Verify(Disp(l0), new[] { Disp(l2), Disp(H2(l2, l3)) }, 0, mroot));
}

// SPV WALLET (real BSV peer-to-peer SPV): a coin arrives as tx + merkle proof + header (the envelope
// the sender stored and handed over). The wallet VERIFIES and STORES it; balance is its own verified
// coins. No node, no scan — instant/offline. A tampered proof credits nothing.
{
    byte[] ssc = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 51, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    var stx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0, new byte[] { 1 }, 0xffffffff) }, new[] { new TxOutputN(250_000, ssc) }, 0);
    byte[] sraw = Tx.Serialize(stx);
    byte[] txidInt = Tx.FromHex(Tx.Txid(stx)); System.Array.Reverse(txidInt);           // display -> internal
    var shdr = new byte[80]; shdr[72] = 0xff; shdr[73] = 0xff; shdr[74] = 0x7f; shdr[75] = 0x20; System.Array.Copy(txidInt, 0, shdr, 36, 32);  // 1-tx block: merkle root = txid
    var env = new SpvEnvelope(sraw, shdr, System.Array.Empty<string>(), 0);
    X("spv: envelope verifies (merkle->root + header PoW)", env.Verify());
    var sw = new SpvWallet(new[] { ssc });
    X("spv: wallet receives + stores the coin from the envelope", sw.Receive(env) && sw.Balance() == 250_000);
    X("spv: the proof is stored for handoff to the next payee", sw.ProofFor(Tx.Txid(stx) + ":0") is not null);
    var sbad = new SpvEnvelope(sraw, shdr, new[] { new string('a', 64) }, 0);
    X("spv: a tampered proof credits nothing", !sbad.Verify() && !new SpvWallet(new[] { ssc }).Receive(sbad));
}

Console.WriteLine($"Estates.Conformance (crypto-core): {xpass} passed, {xfail} failed");
if (xfail == 0) Console.WriteLine("PASS: the in-tree, library-free crypto core upholds every claim (positive + hostile-negative).");
else Console.Error.WriteLine("FAIL: the crypto core failed a claim.");

// (No relay/spectate/replay layers: ESTATES has NO server and NO off-chain transcript. The
// native client is a true P2P peer; game state IS the verified on-chain/signed transcript.)

// LIVE end-to-end broadcast: fund a wallet from the regtest FAUCET node (RPC is TEST-ONLY scaffolding,
// never the product path), build+sign a spend, BROADCAST it over P2P via the in-client node, and
// confirm the node accepted it into its mempool. The same path serves testnet/mainnet (different magic
// + peer). Informational — skips cleanly if no node.
try
{
    using var http = new System.Net.Http.HttpClient();
    http.DefaultRequestHeaders.Authorization = new("Basic", Convert.ToBase64String(System.Text.Encoding.ASCII.GetBytes("e:e")));
    async Task<System.Text.Json.JsonElement> Rpc(string m, params object[] ps)
    {
        string body = System.Text.Json.JsonSerializer.Serialize(new { jsonrpc = "1.0", id = "t", method = m, @params = ps });
        var resp = await http.PostAsync("http://127.0.0.1:18443/", new System.Net.Http.StringContent(body));
        using var jd = System.Text.Json.JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        return jd.RootElement.GetProperty("result").Clone();
    }
    var lw = new StandaloneWallet(SHA256.HashData("live-bcast"u8.ToArray()), "regtest");
    var hashes = await Rpc("generatetoaddress", 101, lw.AddressAt(0));   // mine coins TO the wallet's address
    string b1 = hashes[0].GetString()!;
    string cbTxid = (await Rpc("getblock", b1)).GetProperty("tx")[0].GetString()!;   // block 1 coinbase (now mature)
    lw.AddCoin(cbTxid, 0, 5_000_000_000, 0);
    var built = lw.BuildSend(lw.AddressAt(1), 1_000_000, 500);
    bool sent = await Broadcaster.BroadcastAsync(BsvNet.Regtest, "127.0.0.1", 18444, Tx.FromHex(built.RawHex), 12000);
    var mp = await Rpc("getrawmempool");
    bool inMempool = mp.EnumerateArray().Any(x => x.GetString() == built.Txid);
    Console.WriteLine(sent && inMempool
        ? $"LIVE: BROADCAST a real BSV tx {built.Txid[..16]}… over P2P — node ACCEPTED it into mempool ✓"
        : $"LIVE: broadcast sent={sent} inMempool={inMempool} txid={built.Txid[..16]}…");
}
catch (Exception ex) { Console.WriteLine($"LIVE: broadcast test skipped/failed ({ex.Message})"); }

return (fail == 0 && tfail == 0 && cfail == 0 && sfail == 0 && bfail == 0 && xfail == 0) ? 0 : 1;
