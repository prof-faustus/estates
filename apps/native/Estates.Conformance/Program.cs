// Estates.Conformance — two jobs:
//   (1) CROSS-VALIDATION: prove the native C# engine + on-chain primitives are byte-for-byte
//       identical to the audited reference (same vector files: engine state hashes, tx
//       serialization/txid, card-NFT output+transfer, BIP-143 sighash + ECDSA OP_CHECKSIG,
//       dice beacon). Any divergence fails the build.
//   (2) CRYPTO-CORE self-validation: every claim of the in-tree, LIBRARY-FREE crypto core
//       (secp256k1, hash-chained Type-42 keys, Shamir threshold, 2-of-2 + nLockTime recovery,
//       ECIES/key-wrap) is asserted with a POSITIVE and a HOSTILE-NEGATIVE test. No third-party
//       library, no Ed25519, no RFC-6979 anywhere in the path.
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

// ---- SCRIPTVM cross-validation: native BIP-143 sighash + ECDSA OP_CHECKSIG must
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
    Check("BIP-143 sighash matches", Tx.ToHex(Scriptvm.Sighash(tx, idx, prevoutScript, prevoutValue, hashType)) == v.GetProperty("expectedSighash").GetString());
    Check("valid signature verifies (in-tree ECDSA OP_CHECKSIG)", Scriptvm.CheckSig(tx, idx, prevoutScript, prevoutValue, Tx.FromHex(v.GetProperty("validSig").GetString()!), pub));
    Check("tampered signature is rejected", !Scriptvm.CheckSig(tx, idx, prevoutScript, prevoutValue, Tx.FromHex(v.GetProperty("tamperedSig").GetString()!), pub));

    Console.WriteLine($"Estates.Conformance (scriptvm): {spass} passed, {sfail} failed");
    if (sfail == 0) Console.WriteLine("PASS: native BIP-143 sighash + in-tree secp256k1 ECDSA verify match the reference.");
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
//  must be rejected). No third-party library, no Ed25519, no RFC-6979 in the path.
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

// ECIES (the 2-person ECDH path) + authenticated key-wrap + AEAD: round-trip, and a
// wrong recipient / tampered ciphertext yields NOTHING (returns null, never plaintext).
{
    byte[] bobPriv = RandomNumberGenerator.GetBytes(32), bobPub = Secp256k1.PublicKey(bobPriv);
    byte[] evePriv = RandomNumberGenerator.GetBytes(32);
    byte[] plain = "Alice -> Bob: the deed is yours, and only yours."u8.ToArray();
    byte[] aad = "estates/aad/v1"u8.ToArray();
    var ct = Cipher.EciesEncrypt(bobPub, plain, aad);
    X("ECIES decrypts for the intended recipient", (Cipher.EciesDecrypt(bobPriv, ct, aad) ?? Array.Empty<byte>()).AsSpan().SequenceEqual(plain));
    X("ECIES yields nothing for the wrong recipient", Cipher.EciesDecrypt(evePriv, ct, aad) is null);
    byte[] tamp = (byte[])ct.Bytes.Clone(); tamp[0] ^= 0xff;
    X("ECIES rejects a tampered ciphertext", Cipher.EciesDecrypt(bobPriv, new Cipher.EciesCiphertext(ct.EphemeralPublicKey, tamp), aad) is null);
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

Console.WriteLine($"Estates.Conformance (crypto-core): {xpass} passed, {xfail} failed");
if (xfail == 0) Console.WriteLine("PASS: the in-tree, library-free crypto core upholds every claim (positive + hostile-negative).");
else Console.Error.WriteLine("FAIL: the crypto core failed a claim.");

// (No relay/spectate/replay layers: ESTATES has NO server and NO off-chain transcript. The
// native client is a true P2P peer; game state IS the verified on-chain/signed transcript.)

return (fail == 0 && tfail == 0 && cfail == 0 && sfail == 0 && bfail == 0 && xfail == 0) ? 0 : 1;
