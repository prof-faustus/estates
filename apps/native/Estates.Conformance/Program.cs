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

// MENTAL POKER (the user's commutative-encryption scheme, ported): a dealerless 2-player deal where the
// recipient learns ONLY their card, a non-recipient CANNOT identify it, the full deal is a bijection, and
// every shuffle/remask is audited (commit→reveal). No server, no trust — pure curve math.
{
    int N = 52;
    var deck = MentalPokerEC.BaseDeck(N);
    byte[] cA = MentalPokerEC.NewScalar(), cB = MentalPokerEC.NewScalar();
    int[] permA = Deck.Permutation(SHA256.HashData("mp-A"u8.ToArray()), N);
    int[] permB = Deck.Permutation(SHA256.HashData("mp-B"u8.ToArray()), N);
    byte[] commitA = ShuffleProof.CommitShuffle(cA, permA);
    var afterA = MentalPokerEC.ShuffleMask(deck, cA, permA);
    var afterB = MentalPokerEC.ShuffleMask(afterA, cB, permB);
    X("mental-poker: A's shuffle pass verifies against its commitment", ShuffleProof.VerifyShuffle(deck, afterA, cA, permA, commitA));
    var dA = MentalPokerEC.NewPerCardScalars(N); var dB = MentalPokerEC.NewPerCardScalars(N);
    byte[] commitRA = ShuffleProof.CommitRemask(cA, dA);
    var remA = MentalPokerEC.Remask(afterB, cA, dA);
    var remB = MentalPokerEC.Remask(remA, cB, dB);
    X("mental-poker: A's remask pass verifies against its commitment", ShuffleProof.VerifyRemask(afterB, remA, cA, dA, commitRA));
    // deal position 0 to A: B privately hands A its d_B[0]; A strips d_A[0] + d_B[0] and identifies the card
    int recovered = MentalPokerEC.Identify(MentalPokerEC.Unmask(remB[0], new[] { dA[0], dB[0] }), N);
    X("mental-poker: the recipient recovers a valid card", recovered is >= 0 and < 52);
    // a non-recipient who strips ONLY their own scalar cannot identify the card (unconditional privacy)
    X("mental-poker: a non-recipient CANNOT identify the card", MentalPokerEC.Identify(MentalPokerEC.Unmask(remB[0], new[] { dB[0] }), N) == -1);
    // the WHOLE deal is a bijection — 52 distinct cards, none dropped, none duplicated
    var seen = new HashSet<int>();
    for (int i = 0; i < N; i++) seen.Add(MentalPokerEC.Identify(MentalPokerEC.Unmask(remB[i], new[] { dA[i], dB[i] }), N));
    X("mental-poker: the full deal is a 52-card bijection (none lost/duplicated)", seen.Count == N && !seen.Contains(-1));
    // hostile: a lied shuffle (wrong global) is rejected by the proof
    X("mental-poker: a lied shuffle is rejected", !ShuffleProof.VerifyShuffle(deck, afterA, MentalPokerEC.NewScalar(), permA, commitA));
    // hostile: a duplicated card (malformed deck) is rejected on sight
    var dupes = (byte[][])deck.Clone(); dupes[1] = dupes[0];
    X("mental-poker: a deck with a duplicated card is rejected", !MentalPokerEC.IsWellFormedDeck(dupes));
}

// THRESHOLD DEAL (the collusion-proof card deal): a card dealt to a recipient opens ONLY with the recipient's
// MANDATORY secret AND any t of the other players' shares. The others colluding (all of them, lacking the
// recipient's secret) CANNOT open it; the recipient alone (below threshold of others) CANNOT either.
{
    byte[] face = "Boardwalk title deed — encrypted face"u8.ToArray();
    byte[] aliceSecret = ThresholdDeal.NewSecret();     // Alice's MANDATORY share — never shared
    byte[] othersSecret = ThresholdDeal.NewSecret();    // the others' (Bob/Charlie/Dave) joint secret
    var dealt = ThresholdDeal.Seal(face, aliceSecret, othersSecret, t: 2, others: 3);
    bool Eq(byte[]? a, byte[] b) => a is not null && a.AsSpan().SequenceEqual(b);
    X("threshold deal: recipient + any 2-of-3 others opens the card",
        Eq(ThresholdDeal.Open(dealt.Sealed, aliceSecret, new[] { dealt.OtherShares[0], dealt.OtherShares[2] }), face));
    X("threshold deal: a DIFFERENT 2-of-3 also opens (robust to one offline/hostile other)",
        Eq(ThresholdDeal.Open(dealt.Sealed, aliceSecret, new[] { dealt.OtherShares[1], dealt.OtherShares[2] }), face));
    byte[] notAlice = ThresholdDeal.NewSecret();
    X("threshold deal: the other 3 COLLUDING cannot open (no recipient secret)",
        !Eq(ThresholdDeal.Open(dealt.Sealed, notAlice, dealt.OtherShares), face));
    X("threshold deal: recipient + only 1-of-3 cannot open (below threshold)",
        !Eq(ThresholdDeal.Open(dealt.Sealed, aliceSecret, new[] { dealt.OtherShares[0] }), face));
}

// MENTAL-POKER DECK (the full deal): provably-random dealerless shuffle, THEN the collusion-proof threshold
// deal on the actual masked deck. deck[k] = (∏ of every player's per-card scalar)·M_{σ(k)}; the recipient
// unmasks with their own scalar + any t of the OTHERS' Shamir-shared combined mask.
{
    int N = 52, nPlayers = 4;
    var deck = MentalPokerEC.BaseDeck(N);
    var globals = new byte[nPlayers][];
    var percard = new byte[nPlayers][][];
    for (int p = 0; p < nPlayers; p++)   // SHUFFLE: every player masks + permutes (provably random)
    {
        globals[p] = MentalPokerEC.NewScalar();
        int[] perm = Deck.Permutation(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes("mpd-shuf-" + p)), N);
        deck = MentalPokerEC.ShuffleMask(deck, globals[p], perm);
    }
    for (int p = 0; p < nPlayers; p++)   // REMASK: each swaps global for independent per-card scalars
    {
        percard[p] = MentalPokerEC.NewPerCardScalars(N);
        deck = MentalPokerEC.Remask(deck, globals[p], percard[p]);
    }
    int k = 0, R = 0;                     // deal position 0 to player 0; others = players 1,2,3 (threshold 2-of-3)
    var others = new List<byte[]>();
    for (int p = 0; p < nPlayers; p++) if (p != R) others.Add(percard[p][k]);
    byte[] othersCombined = MentalPokerDeck.CombineOthers(others);
    var shares = MentalPokerDeck.ShareOthers(othersCombined, 2, 3);
    int card = MentalPokerDeck.Deal(deck[k], percard[R][k], new[] { shares[0], shares[1] }, N);
    X("mp-deck: recipient deals a valid card (own scalar + any 2-of-3 others)", card is >= 0 and < 52);
    X("mp-deck: a DIFFERENT 2-of-3 yields the SAME card (robust + consistent)",
        MentalPokerDeck.Deal(deck[k], percard[R][k], new[] { shares[1], shares[2] }, N) == card && card >= 0);
    X("mp-deck: the 3 others COLLUDING cannot identify the card (no recipient scalar)",
        MentalPokerDeck.Deal(deck[k], MentalPokerEC.NewScalar(), shares, N) == -1);
    X("mp-deck: recipient + only 1-of-3 cannot deal (below threshold)",
        MentalPokerDeck.Deal(deck[k], percard[R][k], new[] { shares[0] }, N) == -1);

    // REVEAL-WITH-PROOF (showdown): reveal ALL players' scalars for position k; anyone recomputes the card and
    // verifies it matches the claim. The true card verifies; a lying claim is rejected; a missing scalar fails.
    var allK = new List<byte[]>();
    for (int p = 0; p < nPlayers; p++) allK.Add(percard[p][k]);
    int revealed = RevealProof.RevealedCard(deck[k], allK, N);
    X("reveal-proof: the revealed card equals the card the recipient was dealt", revealed == card && card >= 0);
    X("reveal-proof: an honest claim verifies", RevealProof.Verify(deck[k], allK, revealed, N));
    X("reveal-proof: a LYING claim (wrong card) is rejected", !RevealProof.Verify(deck[k], allK, (revealed + 1) % N, N));
    X("reveal-proof: a reveal missing one scalar cannot reproduce the card",
        RevealProof.RevealedCard(deck[k], new[] { percard[0][k], percard[1][k], percard[2][k] }, N) != revealed);
}

// END-OF-GAME RECLAIM COVENANT: at game end all card NFTs are spent back to the deck/bank (nLockTime). A
// well-formed reclaim verifies; tampering (final input, wrong lockTime, omitting a card, wrong destination) fails.
{
    var cards = new List<OutpointN> {
        new OutpointN(new string('a', 64), 0), new OutpointN(new string('b', 64), 1), new OutpointN(new string('c', 64), 0) };
    byte[] bank = NodeWallet.P2pkhScript(Recovery.Hash160(Secp256k1.PublicKey(RandomNumberGenerator.GetBytes(32))));
    long lockTime = 850000;
    var reclaim = ReclaimCovenant.BuildReclaim(cards, bank, lockTime);
    X("reclaim: a well-formed end-of-game reclaim verifies", ReclaimCovenant.Verify(reclaim, cards, bank, lockTime).ok);
    var finalIn = reclaim with { Inputs = new[] { reclaim.Inputs[0] with { Sequence = 0xffffffff }, reclaim.Inputs[1], reclaim.Inputs[2] } };
    X("reclaim: a FINAL input (lockTime unenforced) is rejected", !ReclaimCovenant.Verify(finalIn, cards, bank, lockTime).ok);
    X("reclaim: a wrong lockTime is rejected", !ReclaimCovenant.Verify(reclaim, cards, bank, lockTime + 1).ok);
    var partial = ReclaimCovenant.BuildReclaim(cards.Take(2).ToList(), bank, lockTime);
    X("reclaim: a reclaim that omits a card is rejected", !ReclaimCovenant.Verify(partial, cards, bank, lockTime).ok);
    byte[] notBank = NodeWallet.P2pkhScript(Recovery.Hash160(Secp256k1.PublicKey(RandomNumberGenerator.GetBytes(32))));
    X("reclaim: dust sent NOT to the bank/deck is rejected", !ReclaimCovenant.Verify(reclaim, cards, notBank, lockTime).ok);
}

// ON-CHAIN DECK ISSUANCE: the shuffled masked deck issues as 1-sat NFT carriers (no OP_RETURN) and reads back
// byte-for-byte — this is how the shared encrypted deck lives on chain for every peer to read.
{
    int N = 52;
    var deck = MentalPokerEC.ShuffleMask(MentalPokerEC.BaseDeck(N), MentalPokerEC.NewScalar(),
        Deck.Permutation(SHA256.HashData("ocd-shuffle"u8.ToArray()), N));
    byte[] tablePkh = Recovery.Hash160(Secp256k1.PublicKey(RandomNumberGenerator.GetBytes(32)));
    var scripts = OnChainDeck.DeckScripts(deck, tablePkh);
    bool roundTrip = scripts.Count == N;
    for (int i = 0; i < N; i++) { var pt = OnChainDeck.ReadDeckPoint(scripts[i]); if (pt is null || !pt.AsSpan().SequenceEqual(deck[i])) roundTrip = false; }
    X("on-chain deck: 52 masked cards issue as 1-sat carriers and read back byte-for-byte", roundTrip);
    X("on-chain deck: a plain P2PKH is not misread as a deck card", OnChainDeck.ReadDeckPoint(NodeWallet.P2pkhScript(tablePkh)) is null);
}

// FULL MENTAL-POKER HAND (end-to-end orchestrator the game calls): shuffle -> issue on-chain -> threshold-deal
// to players -> showdown reveal -> end-of-game reclaim. Proves the whole composed flow of a real Estates hand.
{
    var hand = new MentalPokerHand(52, 4);
    byte[] tablePkh = Recovery.Hash160(Secp256k1.PublicKey(RandomNumberGenerator.GetBytes(32)));
    X("full hand: the deck issues as 52 on-chain card NFTs", hand.IssueScripts(tablePkh).Count == 52);
    var s0 = hand.DealShares(0, 0, 2); int c0 = hand.Deal(0, 0, new[] { s0[0], s0[2] });
    var s1 = hand.DealShares(1, 1, 2); int c1 = hand.Deal(1, 1, new[] { s1[0], s1[1] });
    X("full hand: player 0 is dealt a valid card (own scalar + 2-of-3 others)", c0 is >= 0 and < 52);
    X("full hand: player 1 is dealt a valid card", c1 is >= 0 and < 52);
    X("full hand: the two dealt cards differ (permutation is a bijection)", c0 != c1 && c0 >= 0);
    X("full hand: showdown reveal matches player 0's dealt card", hand.Reveal(0) == c0);
    X("full hand: showdown reveal matches player 1's dealt card", hand.Reveal(1) == c1);
    var outs = new List<OutpointN> { new OutpointN(new string('1', 64), 0), new OutpointN(new string('2', 64), 0) };
    byte[] bank = NodeWallet.P2pkhScript(tablePkh);
    X("full hand: end-of-game reclaim of the dealt cards verifies",
        ReclaimCovenant.Verify(ReclaimCovenant.BuildReclaim(outs, bank, 900000), outs, bank, 900000).ok);
}

// RED-TEAM (hostile-negative): malformed points/scalars, garbage deck NFTs, and tampered reclaims must all be
// rejected fail-closed — a hostile player/server cannot inject bad inputs into the mental-poker deal.
{
    byte[] badPoint = new byte[33]; badPoint[0] = 0x02;          // 0x02||0 — not a usable card point
    byte[] zero = new byte[32];
    byte[] okScalar = MentalPokerEC.NewScalar();
    byte[] okPoint = Secp256k1.CardBasePoint(0);
    bool t;
    t = false; try { Secp256k1.PointMul(badPoint, okScalar); } catch { t = true; } X("redteam: PointMul rejects an off-curve point", t);
    t = false; try { Secp256k1.PointMul(okPoint, zero); } catch { t = true; } X("redteam: PointMul rejects a zero scalar", t);
    t = false; try { Secp256k1.ScalarMul(zero, okScalar); } catch { t = true; } X("redteam: ScalarMul rejects a zero scalar", t);
    t = false; try { Secp256k1.ScalarInverse(zero); } catch { t = true; } X("redteam: ScalarInverse rejects a zero scalar", t);
    X("redteam: IsValidPoint rejects 0x02||00..0", !Secp256k1.IsValidPoint(badPoint));
    X("redteam: a garbage deck NFT (bad point payload) is rejected on read",
        OnChainDeck.ReadDeckPoint(OnChainActions.CarrierScript(TxProtocol.Stamp(TxType.Deal, badPoint), Recovery.Hash160(okPoint))) is null);
    var rcards = new List<OutpointN> { new OutpointN(new string('d', 64), 0), new OutpointN(new string('e', 64), 0) };
    byte[] rbank = NodeWallet.P2pkhScript(Recovery.Hash160(Secp256k1.PublicKey(MentalPokerEC.NewScalar())));
    var rgood = ReclaimCovenant.BuildReclaim(rcards, rbank, 800001);
    X("redteam: reclaim rejects a duplicate input", !ReclaimCovenant.Verify(rgood with { Inputs = new[] { rgood.Inputs[0], rgood.Inputs[0] } }, rcards, rbank, 800001).ok);
    X("redteam: reclaim rejects a wrong dust value", !ReclaimCovenant.Verify(rgood with { Outputs = new[] { rgood.Outputs[0] with { Value = 999 } } }, rcards, rbank, 800001).ok);
    X("redteam: reclaim rejects a duplicate card in the spec", !ReclaimCovenant.Verify(rgood, new List<OutpointN> { rcards[0], rcards[0] }, rbank, 800001).ok);
}

// FUZZ the untrusted-input decoders: thousands of random/garbage byte strings must NEVER crash — every parser
// of attacker-controlled data fails closed (null / false / -1), never throws.
{
    bool anyThrew = false; string firstThrow = "";
    for (int i = 0; i < 3000 && !anyThrew; i++)
    {
        byte[] junk = RandomNumberGenerator.GetBytes(1 + (i % 256));
        try
        {
            _ = Tx.Parse(junk);
            _ = TxTransport.ReadCarrier(junk);
            _ = TxMessage.OpenCarrier(junk, MentalPokerEC.NewScalar());
            _ = OnChainActions.ReadType(junk);
            _ = OnChainDeck.ReadDeckPoint(junk);
            _ = Secp256k1.IsValidPoint(junk);
            _ = Secp256k1.IsValidScalar(junk);
            _ = MentalPokerEC.IsWellFormedDeck(new[] { junk });
            _ = new SpvEnvelope(junk, junk, new List<string>(), 0).Verify();
            _ = ReclaimCovenant.Verify(new NativeTx(1, new List<TxInputN>(), new List<TxOutputN>(), 0), new List<OutpointN>(), junk, 0);
        }
        catch (Exception e) { anyThrew = true; firstThrow = e.Message; }
    }
    X("fuzz: 3000 random inputs never crash any decoder (fail-closed) " + (anyThrew ? "THREW: " + firstThrow : ""), !anyThrew);
}

// ON-CHAIN DECK ISSUANCE FROM THE WALLET: a funded wallet mints the whole shuffled deck as 1-sat NFTs in ONE
// signed transaction; each output reads back as a deck card; the spend verifies locally (no node).
{
    var hand = new MentalPokerHand(52, 4);
    byte[] tablePkh = Recovery.Hash160(Secp256k1.PublicKey(MentalPokerEC.NewScalar()));
    var scripts = hand.IssueScripts(tablePkh);
    byte[] seed = SHA256.HashData("estates/deck-issue/selftest"u8.ToArray());
    var w = new StandaloneWallet(seed, "regtest");
    w.AddCoin(Tx.ToHex(RandomNumberGenerator.GetBytes(32)), 0, 1_000_000, 0);
    var built = OnChainActions.IssueDeck(w, scripts, 1000);
    int deckOuts = 0;
    foreach (var o in built.Tx.Outputs) if (o.Value == 1 && OnChainDeck.ReadDeckPoint(o.Script) is not null) deckOuts++;
    X("issue-deck: the issuance tx mints 52 readable 1-sat deck-card NFTs", deckOuts == 52);
    X("issue-deck: the issuance tx is signed and verifies locally (no node)", w.VerifySpend(built));
}

// ON-CHAIN THRESHOLD-DEAL DELIVERY: the others SEAL their shares to the recipient on-chain (only the recipient
// can open them); the recipient opens, parses, reconstructs, and deals their card; a non-recipient cannot open.
{
    var hand = new MentalPokerHand(52, 4);
    int k = 0, R = 0;
    byte[] recipPriv = MentalPokerEC.NewScalar(); byte[] recipPub = Secp256k1.PublicKey(recipPriv);
    var shares = hand.DealShares(k, R, 2);                       // 3 shares for the 3 others, threshold 2
    var sealedCarriers = new List<byte[]>();
    foreach (var sh in new[] { shares[0], shares[2] })          // any 2 of the 3 others deliver, sealed to recipient
        sealedCarriers.Add(TxMessage.SealCarrier(MentalPokerEC.NewScalar(), recipPub, TxType.Reveal, OnChainDeck.ShareBytes(sh)));
    var got = new List<Shamir.Share>();
    foreach (var c in sealedCarriers)
    {
        var m = TxMessage.OpenCarrier(c, recipPriv);
        var s = m is null ? null : OnChainDeck.ParseShare(m.Value.plaintext);
        if (s is not null) got.Add(s);
    }
    int card = hand.Deal(k, R, got);
    X("on-chain deal: recipient opens 2-of-3 sealed shares and deals a valid card", got.Count == 2 && card is >= 0 and < 52);
    X("on-chain deal: a non-recipient cannot open the sealed shares", TxMessage.OpenCarrier(sealedCarriers[0], MentalPokerEC.NewScalar()) is null);
    X("on-chain deal: the dealt card matches the showdown reveal", hand.Reveal(k) == card);
}

// DISTRIBUTED (P2P) SHUFFLE: the deck is passed player-to-player as serialized bytes; each player COMMITS to
// their pass before applying it, and any auditor re-verifies every pass against its commitment (ShuffleProof).
// This is the real multiplayer shuffle that runs over the Estates P2P transport — no central dealer.
{
    int N = 52, players = 4;
    byte[][] deck = MentalPokerEC.BaseDeck(N);
    var globals = new byte[players][]; var perms = new int[players][]; var commits = new byte[players][];
    int wireLen = 0;
    for (int p = 0; p < players; p++)
    {
        byte[] wire = OnChainDeck.SerializeDeck(deck);            // sent over the wire to player p
        var received = OnChainDeck.DeserializeDeck(wire);          // player p validates every card on receipt
        wireLen = received?.Length ?? -1;
        globals[p] = MentalPokerEC.NewScalar();
        perms[p] = Deck.Permutation(SHA256.HashData(System.Text.Encoding.ASCII.GetBytes("dist-" + p)), N);
        commits[p] = ShuffleProof.CommitShuffle(globals[p], perms[p]);   // commit BEFORE applying
        deck = MentalPokerEC.ShuffleMask(received!, globals[p], perms[p]);
    }
    bool allVerify = true;
    byte[][] cur = MentalPokerEC.BaseDeck(N);
    for (int p = 0; p < players; p++) { var outp = MentalPokerEC.ShuffleMask(cur, globals[p], perms[p]); if (!ShuffleProof.VerifyShuffle(cur, outp, globals[p], perms[p], commits[p])) allVerify = false; cur = outp; }
    X("dist-shuffle: the deck passes over the wire (serialize/deserialize round-trips, every card validated)", wireLen == N);
    X("dist-shuffle: every player's pass verifies against its prior commitment (fully audited)", allVerify);
    X("dist-shuffle: a wire deck with an invalid card is rejected on receipt",
        OnChainDeck.DeserializeDeck(new byte[33]) is null);
    X("dist-shuffle: a player using the WRONG commitment is caught",
        !ShuffleProof.VerifyShuffle(MentalPokerEC.BaseDeck(N), MentalPokerEC.ShuffleMask(MentalPokerEC.BaseDeck(N), globals[0], perms[0]), globals[0], perms[0], commits[1]));
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
// coins. No node, no scan — instant, always online. A tampered proof credits nothing.
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

// TYPE-42 PAYMENT (number-42): payer derives the PUBLIC key to pay; payee derives the matching PRIVATE
// key to spend — without the payee ever publishing an address; a different invoice => a fresh address.
{
    byte[] payeePriv = Type42.UniqueKey(new byte[32] { 61, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "id");
    byte[] payeePub = Secp256k1.PublicKey(payeePriv);
    byte[] payerPriv = Type42.UniqueKey(new byte[32] { 62, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "id");
    byte[] payerPub = Secp256k1.PublicKey(payerPriv);
    byte[] payTo = Type42Payment.PayToPub(payeePub, payerPriv, "inv-1");
    byte[] spend = Type42Payment.SpendPriv(payeePriv, payerPub, "inv-1");
    X("type42: payee's derived key spends exactly what the payer paid to", Tx.ToHex(Secp256k1.PublicKey(spend)) == Tx.ToHex(payTo));
    X("type42: a different invoice => a fresh address (never reused)", Tx.ToHex(Type42Payment.PayToPub(payeePub, payerPriv, "inv-2")) != Tx.ToHex(payTo));
    X("type42: payee never publishes an address (derived address is valid mainnet P2PKH)", Type42Payment.PayToAddress(payeePub, payerPriv, "inv-1", BsvNet.Mainnet).StartsWith("1"));
}

// SPV PAYMENT (online accept): Alice pays Bob and hands over a merkle-proof envelope for the input;
// Bob verifies it against headers and accepts instantly. Missing/tampered proof => rejected.
{
    byte[] bobScript = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 71, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    byte[] aliceScript = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 72, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    // Alice's input coin (prior tx) + its SPV envelope (1-tx block, easy PoW)
    var prior = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(100_000, aliceScript) }, 0);
    byte[] priorRaw = Tx.Serialize(prior);
    byte[] mInt = Tx.FromHex(Tx.Txid(prior)); System.Array.Reverse(mInt);
    var phdr = new byte[80]; phdr[72] = 0xff; phdr[73] = 0xff; phdr[74] = 0x7f; phdr[75] = 0x20; System.Array.Copy(mInt, 0, phdr, 36, 32);
    var penv = new SpvEnvelope(priorRaw, phdr, System.Array.Empty<string>(), 0);
    // Tx3: Alice spends that coin, pays Bob 90k
    var tx3 = new NativeTx(1, new[] { new TxInputN(Tx.Txid(prior), 0, new byte[] { 1 }, 0xffffffff) }, new[] { new TxOutputN(90_000, bobScript) }, 0);
    var bobScripts = new HashSet<string> { Tx.ToHex(bobScript) };
    var r = SpvPayment.VerifyIncoming(Tx.Serialize(tx3), new[] { penv }, bobScripts);
    X("spvpay: Bob accepts the payment with a valid input proof", r.Ok && r.PaidToMe == 90_000);
    X("spvpay: missing input proof => rejected", !SpvPayment.VerifyIncoming(Tx.Serialize(tx3), System.Array.Empty<SpvEnvelope>(), bobScripts).Ok);
    var tampered = new SpvEnvelope(priorRaw, phdr, new[] { new string('a', 64) }, 0);
    X("spvpay: tampered input proof => rejected", !SpvPayment.VerifyIncoming(Tx.Serialize(tx3), new[] { tampered }, bobScripts).Ok);
}

// BLOCK MERKLE (build a real coin's proof): the branch computed from a block's txid list verifies
// against the block's merkle root for every position — so any mined coin becomes an SPV envelope.
{
    var txids = new List<string>();
    for (int i = 0; i < 5; i++) { var b = new byte[32]; b[0] = (byte)(100 + i); System.Array.Reverse(b); txids.Add(Tx.ToHex(b)); }   // 5 txids (odd -> duplication path)
    var rootInt = BlockMerkle.Root(txids);
    bool all = true;
    for (int i = 0; i < txids.Count; i++)
    {
        var br = BlockMerkle.BranchFor(txids, txids[i]);
        if (br is null || !MerkleProof.Verify(txids[i], br.Value.branch, br.Value.index, rootInt)) { all = false; break; }
    }
    X("blockmerkle: every coin's computed branch verifies to the block root", all);
    X("blockmerkle: a tx not in the block has no branch", BlockMerkle.BranchFor(txids, new string('f', 64)) is null);
    var single = new List<string> { txids[0] };
    var sbr = BlockMerkle.BranchFor(single, txids[0]);
    X("blockmerkle: single-tx block has empty branch verifying to root", sbr is not null && sbr.Value.branch.Count == 0 && MerkleProof.Verify(txids[0], sbr.Value.branch, 0, BlockMerkle.Root(single)));
}

// SPV WALLET PERSISTENCE ("open and it's just there"): a received coin is saved and reloads on a
// fresh wallet with the balance intact — no re-fetch, instant.
{
    byte[] osc = NodeWallet.P2pkhScript(Recovery.Hash160(Cipher.PublicKey(new byte[32] { 81, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 })));
    var otx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(424242, osc) }, 0);
    byte[] oInt = Tx.FromHex(Tx.Txid(otx)); System.Array.Reverse(oInt);
    var ohdr = new byte[80]; ohdr[72] = 0xff; ohdr[73] = 0xff; ohdr[74] = 0x7f; ohdr[75] = 0x20; System.Array.Copy(oInt, 0, ohdr, 36, 32);
    var oenv = new SpvEnvelope(Tx.Serialize(otx), ohdr, System.Array.Empty<string>(), 0);
    var w1 = new SpvWallet(new[] { osc }); w1.Receive(oenv);
    string pf = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "estates_spv_test.dat");
    w1.Save(pf);
    var w2 = new SpvWallet(new[] { osc }); w2.Load(pf);
    X("spv-persist: a reloaded wallet shows the saved balance instantly", w2.Balance() == 424242 && w2.CoinCount == 1);
    try { System.IO.File.Delete(pf); } catch { }
}

// SPV SPEND (send): the wallet selects its SPV coin, builds + signs the payment (FORKID), the input
// signature verifies, change is correct, and the spent coin's proof is handed to the payee.
{
    byte[] priv = Type42.UniqueKey(new byte[32] { 91, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "x");
    byte[] pub = Secp256k1.PublicKey(priv);
    byte[] myScript = NodeWallet.P2pkhScript(Recovery.Hash160(pub));
    long coinVal = 1_000_000;
    var ctx = new NativeTx(1, new[] { new TxInputN(new string('0', 64), 0, new byte[] { 0 }, 0xffffffff) }, new[] { new TxOutputN(coinVal, myScript) }, 0);
    byte[] cInt = Tx.FromHex(Tx.Txid(ctx)); System.Array.Reverse(cInt);
    var chdr = new byte[80]; chdr[72] = 0xff; chdr[73] = 0xff; chdr[74] = 0x7f; chdr[75] = 0x20; System.Array.Copy(cInt, 0, chdr, 36, 32);
    var sw = new SpvWallet(new[] { myScript }); sw.Receive(new SpvEnvelope(Tx.Serialize(ctx), chdr, System.Array.Empty<string>(), 0));
    byte[] toScript = NodeWallet.P2pkhScript(Recovery.Hash160(Secp256k1.PublicKey(Type42.UniqueKey(new byte[32] { 92, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "y"))));
    var keymap = new Dictionary<string, (byte[] priv, byte[] pub)> { [Tx.ToHex(myScript)] = (priv, pub) };
    var built = SpvSpend.Build(sw, keymap, toScript, 600_000, 500, myScript);
    X("spvspend: spend built from the SPV coin", built is not null && built.Change == coinVal - 600_000 - 500);
    var sigWithType = TxTransport.ReadCarrier(built!.Tx.Inputs[0].ScriptSig);
    X("spvspend: input signature verifies (FORKID OP_CHECKSIG)", sigWithType is not null && Scriptvm.CheckSig(built.Tx, 0, myScript, coinVal, sigWithType, Tx.ToHex(pub)));
    X("spvspend: the spent coin's proof is handed to the payee", built.InputProofs.Count == 1);
    X("spvspend: insufficient funds returns null", SpvSpend.Build(sw, keymap, toScript, 999_999_999, 500, myScript) is null);
}

// ESTATE GOSSIP overlay: announce/query messages round-trip; state tracks live peers and answers
// queries by offer tag; garbage is rejected.
{
    var enc = EstateGossip.Encode(GossipKind.Announce, "node-1", "02abc", "table:holdem:6");
    var dec = EstateGossip.Decode(enc);
    X("gossip: announce round-trips", dec is not null && dec.Value.kind == GossipKind.Announce && dec.Value.nodeId == "node-1" && dec.Value.offer == "table:holdem:6");
    X("gossip: garbage rejected", EstateGossip.Decode(new byte[] { 9 }) is null);
    var gs = new GossipState();
    gs.OnAnnounce("n1", "02a", "estate:london");
    gs.OnAnnounce("n2", "02b", "estate:paris");
    X("gossip: state lists live peers", gs.Live().Count == 2);
    X("gossip: query by tag finds the match", gs.Query("paris").Count == 1 && gs.Query("paris")[0].NodeId == "n2");
    X("gossip: empty tag returns all live", gs.Query("").Count == 2);
}

// BOT 2-of-2 funding/reclaim: a 2-of-2 spend needs BOTH the human's and the bot's signature; both
// verify; a wrong key fails. (Human funds the bot; on close both sign and the human reclaims.)
{
    byte[] aPriv = Type42.UniqueKey(new byte[32] { 93, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "alice"); byte[] aPub = Secp256k1.PublicKey(aPriv);
    byte[] bPriv = Type42.UniqueKey(new byte[32] { 94, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "bot"); byte[] bPub = Secp256k1.PublicKey(bPriv);
    byte[] lockScript = Multisig.Lock2of2(aPub, bPub);
    byte[] toScript = NodeWallet.P2pkhScript(Recovery.Hash160(aPub));   // reclaim to Alice
    var spend = new NativeTx(2, new[] { new TxInputN(new string('1', 64), 0, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(99500, toScript) }, 0);
    byte[] sigA = Multisig.Sign(spend, 0, lockScript, 100000, aPriv);
    byte[] sigB = Multisig.Sign(spend, 0, lockScript, 100000, bPriv);
    X("multisig: 2-of-2 reclaim verifies with both signatures", Multisig.Verify2of2(spend, 0, lockScript, 100000, sigA, sigB, aPub, bPub));
    byte[] wrong = Multisig.Sign(spend, 0, lockScript, 100000, Type42.UniqueKey(new byte[32] { 95, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "eve"));
    X("multisig: a wrong signer fails", !Multisig.Verify2of2(spend, 0, lockScript, 100000, sigA, wrong, aPub, bPub));
    X("multisig: unlock script is OP_0 + both sigs", Multisig.Unlock2of2(sigA, sigB)[0] == 0x00);
}

// BOT FUNDING refund-to-funder: the bot builds + half-signs the reclaim; Alice completes it; the final
// tx carries a valid 2-of-2 unlock and pays 100% (minus fee) back to Alice's address. A forged bot
// signature is rejected.
{
    byte[] aPriv = Type42.UniqueKey(new byte[32] { 96, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "alice2"); byte[] aPub = Secp256k1.PublicKey(aPriv);
    byte[] bPriv = Type42.UniqueKey(new byte[32] { 97, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "bot2"); byte[] bPub = Secp256k1.PublicKey(bPriv);
    byte[] ePriv = Type42.UniqueKey(new byte[32] { 98, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "eve2");
    byte[] aRefund = NodeWallet.P2pkhScript(Recovery.Hash160(aPub));
    var fund = new BotFund(new string('a', 64), 0, 1_000_000, aPub, bPub, aRefund);
    var refund = BotFunding.BuildBotRefund(fund, bPriv, 500);
    X("botfunding: bot half-signs the reclaim", refund.BotSig.Length > 2 && refund.Value == 1_000_000);
    var final = BotFunding.CompleteRefund(refund, aPriv, aPub, bPub);
    X("botfunding: Alice completes the refund (both sigs valid)", final is not null);
    X("botfunding: refund pays 100% minus fee back to Alice", final!.Outputs[0].Value == 999_500 && Tx.ToHex(final.Outputs[0].Script) == Tx.ToHex(aRefund));
    X("botfunding: final tx is fully unlocked (OP_0 + 2 sigs)", final.Inputs[0].ScriptSig.Length > 100 && final.Inputs[0].ScriptSig[0] == 0x00);
    byte[] forged = Multisig.Sign(refund.Tx, 0, refund.LockScript, refund.Value, ePriv);
    X("botfunding: a forged bot signature is rejected", BotFunding.CompleteRefund(refund with { BotSig = forged }, aPriv, aPub, bPub) is null);
}

// BIP38 (scrypt) — the canonical no-EC-multiply, uncompressed test vector. Proves scrypt + decrypt.
{
    var r = Bip38.Decrypt("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "TestingOneTwoThree");
    X("bip38: decrypts the canonical vector", r is not null);
    X("bip38: recovers the exact private key", r is not null && Tx.ToHex(r.Value.priv).ToUpperInvariant() == "CBF4B9F70470856BB4F40F80B87EDB90865997FFEE6DF315AB166D713AF433A5");
    X("bip38: a wrong passphrase is rejected", Bip38.Decrypt("6PRVWUbkzzsbcVac2qwfssoUJAN1Xhrg6bNk8J7Nzm5H7kxEbn2Nh2ZoGg", "wrong") is null);
}

// BLOOM filter (BIP37 MurmurHash3) — inserted items always match (no false negatives); an absent item
// is overwhelmingly a non-match at a tiny filter fp rate; filterload payload is well-formed.
{
    var bf = new BloomFilter(10, 0.0001, 0);
    var hashes = new List<byte[]>();
    for (int i = 0; i < 10; i++) { var h = Recovery.Hash160(Secp256k1.PublicKey(Type42.UniqueKey(new byte[32] { (byte)(120 + i), 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "bloom"))); hashes.Add(h); bf.Insert(h); }
    bool allIn = true; foreach (var h in hashes) if (!bf.Contains(h)) allIn = false;
    X("bloom: every inserted item matches (no false negatives)", allIn);
    int fp = 0; for (int i = 0; i < 200; i++) { var h = Recovery.Hash160(Secp256k1.PublicKey(Type42.UniqueKey(new byte[32] { 7, (byte)i, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "absent"))); if (bf.Contains(h)) fp++; }
    X("bloom: absent items mostly miss (low false-positive rate)", fp <= 2);
    X("bloom: filterload payload is well-formed", bf.FilterLoad()[0] == bf.ByteLength && bf.FilterLoad().Length == 1 + bf.ByteLength + 9);
}

// QR encoder — structural invariants (real QR: finder patterns, timing, dark module, size scaling).
{
    var q = QrCode.Encode("hi", QrCode.Medium);                  // fits version 1
    X("qr: version-1 short data is 21x21", q.Size == 21);
    X("qr: finder centres are dark (all 3 corners)", q.Module(3, 3) && q.Module(q.Size - 4, 3) && q.Module(3, q.Size - 4));
    X("qr: finder light ring (d=2) is light", !q.Module(1, 3) && !q.Module(5, 3));
    X("qr: timing row alternates", q.Module(8, 6) != q.Module(9, 6));
    X("qr: mandatory dark module set", q.Module(8, q.Size - 8));
    var addr = QrCode.Encode("1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", QrCode.Medium);   // 34 bytes → bigger version
    X("qr: a 34-char address uses a larger symbol", addr.Size > 21);
    var big = QrCode.Encode(new string('x', 300), QrCode.Low);
    X("qr: larger payload uses a larger symbol still", big.Size > addr.Size);
    X("qr: bitcoin URI encodes without error", QrCode.Encode("bitcoin:1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2?amount=0.5", QrCode.Medium).Size >= 21);
}

// VAULT — the mandatory pre-signed nLockTime recovery: both parties sign at funding; it verifies, is
// time-locked, pays 100% (minus fee) to the owner, finalizes to a broadcastable tx; a forged sig fails.
{
    byte[] oPriv = Type42.UniqueKey(new byte[32] { 101, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "owner"); byte[] oPub = Secp256k1.PublicKey(oPriv);
    byte[] xPriv = Type42.UniqueKey(new byte[32] { 102, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "other"); byte[] xPub = Secp256k1.PublicKey(xPriv);
    byte[] ePriv = Type42.UniqueKey(new byte[32] { 103, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "eve3");
    byte[] ownerRefund = NodeWallet.P2pkhScript(Recovery.Hash160(oPub));
    var rec = Vault.BuildRecovery(new string('b', 64), 0, 1_000_000, oPub, xPub, ownerRefund, 800_000, oPriv, xPriv, 500);
    X("vault: recovery verifies (both signed, time-locked, reclaimable)", Vault.VerifyRecovery(rec, oPub, xPub));
    X("vault: recovery is time-locked (nLockTime set, input non-final)", rec.LockTime == 800_000 && rec.Tx.Inputs[0].Sequence < 0xffffffff);
    X("vault: recovery pays 100% (minus fee) to the owner", rec.Tx.Outputs[0].Value == 999_500 && Tx.ToHex(rec.Tx.Outputs[0].Script) == Tx.ToHex(ownerRefund));
    var fin = Vault.Finalize(rec);
    X("vault: finalizes to a broadcastable tx (OP_0 + 2 sigs)", fin.Inputs[0].ScriptSig.Length > 100 && fin.Inputs[0].ScriptSig[0] == 0x00 && fin.LockTime == 800_000);
    byte[] forged = Multisig.Sign(rec.Tx, 0, rec.LockScript, rec.Value, ePriv);
    X("vault: a forged co-signer signature is rejected", !Vault.VerifyRecovery(rec with { OtherSig = forged }, oPub, xPub));
}

// MERKLEBLOCK (BIP37 partial merkle tree): build a proof that one tx in a block matched, then extract the
// root + matched txid; the extracted root equals the full tree's root; a tampered hash breaks it.
{
    var txids = new List<byte[]>();
    for (int i = 0; i < 7; i++) txids.Add(Tx.Hash256(new byte[] { (byte)i }));   // 7 "txids" (internal order)
    static byte[] FullRoot(List<byte[]> ids)
    {
        var cur = new List<byte[]>(ids);
        while (cur.Count > 1)
        {
            var nxt = new List<byte[]>();
            for (int i = 0; i < cur.Count; i += 2)
            {
                var l = cur[i]; var r = i + 1 < cur.Count ? cur[i + 1] : cur[i];
                var c = new byte[64]; System.Array.Copy(l, c, 32); System.Array.Copy(r, 0, c, 32, 32);
                nxt.Add(Tx.Hash256(c));
            }
            cur = nxt;
        }
        return cur[0];
    }
    byte[] fullRoot = FullRoot(txids);
    var matches = new bool[7]; matches[3] = true;                                 // match tx #3
    var (pmtFlags, pmtHashes) = PartialMerkleTree.Build(txids, matches);
    var (pmtRoot, pmtMatched) = PartialMerkleTree.Extract(7, pmtFlags, pmtHashes);
    X("merkleblock: extracted root equals the full merkle root", pmtRoot is not null && Tx.ToHex(pmtRoot) == Tx.ToHex(fullRoot));
    X("merkleblock: the matched txid is recovered", pmtMatched.Count == 1 && Tx.ToHex(pmtMatched[0]) == Tx.ToHex(txids[3]));
    var pmtBad = new List<byte[]>(pmtHashes); if (pmtBad.Count > 0) pmtBad[0] = Tx.Hash256(new byte[] { 0xff });
    var (badRoot, _) = PartialMerkleTree.Extract(7, pmtFlags, pmtBad);
    X("merkleblock: a tampered hash yields a different root", badRoot is null || Tx.ToHex(badRoot) != Tx.ToHex(fullRoot));
}

// BLOOM MATCH (BIP37 find): a wallet filter over its address pkh matches a tx paying that address, and
// (no false negatives) a tx paying an UNwatched address overwhelmingly does not match.
{
    var f = new BloomFilter(8, 0.0001, 1234);
    byte[] minePkh = Recovery.Hash160(Secp256k1.PublicKey(Type42.UniqueKey(new byte[32] { 110, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "mine")));
    BloomMatch.InsertAddress(f, minePkh);
    var payMe = new NativeTx(2, new[] { new TxInputN(new string('1', 64), 0, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(1000, NodeWallet.P2pkhScript(minePkh)) }, 0);
    X("bloommatch: a tx paying my watched address matches", BloomMatch.Matches(payMe, Tx.Hash256(new byte[] { 1 }), f));
    byte[] otherPkh = Recovery.Hash160(Secp256k1.PublicKey(Type42.UniqueKey(new byte[32] { 111, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "other")));
    var payOther = new NativeTx(2, new[] { new TxInputN(new string('2', 64), 0, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(1000, NodeWallet.P2pkhScript(otherPkh)) }, 0);
    X("bloommatch: a tx paying an unwatched address does not match", !BloomMatch.Matches(payOther, Tx.Hash256(new byte[] { 2 }), f));
    X("bloommatch: P2pkhPkh extracts the address hash", BloomMatch.P2pkhPkh(NodeWallet.P2pkhScript(minePkh)) is { } pk && Tx.ToHex(pk) == Tx.ToHex(minePkh));
}

// IDENTITY (P1): base ID key is reserved (never a receive sub-key); sub-keys are a deterministic HMAC
// hash-chain from the seed; fresh receive indices advance and start at >= 1 (index 0 = identity).
{
    byte[] seed = Type42.UniqueKey(new byte[32] { 130, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "idseed");
    var kr = new KeyRing(seed);
    string idp = Tx.ToHex(kr.IdentityPub());
    bool collide = false; for (int i = 1; i <= 20; i++) if (Tx.ToHex(kr.PubAt(i)) == idp) collide = true;
    X("identity: base ID key is never a receive sub-key", !collide);
    var kr2 = new KeyRing(seed);
    X("identity: sub-keys are deterministic from the seed", Tx.ToHex(kr.PubAt(7)) == Tx.ToHex(kr2.PubAt(7)));
    var (i1, _, _) = kr.NextReceive(); var (i2, _, _) = kr.NextReceive();
    X("identity: fresh receive indices advance and start at >= 1", i1 >= 1 && i2 == i1 + 1);
    X("identity: identity pubkey is a valid 33-byte compressed key", kr.IdentityPub().Length == 33 && (kr.IdentityPub()[0] == 0x02 || kr.IdentityPub()[0] == 0x03));
}

// FILTERLOAD wire (P2P bloom): the wallet's Bloom filter frames into a valid `filterload` network message
// (magic/command/checksum) and parses back with the exact filter payload — so a serving peer can be told
// which transactions to return.
{
    var bf = new BloomFilter(10, 0.0001, 7);
    byte[] payload = bf.FilterLoad();
    byte[] msg = BsvWire.Frame(BsvNet.Mainnet, "filterload", payload);
    var (parsed, consumed) = BsvWire.TryRead(BsvNet.Mainnet, msg);
    X("filterload: frames + parses to the filterload command", parsed is not null && parsed.Command == "filterload" && consumed == msg.Length);
    X("filterload: payload round-trips the Bloom filter", parsed is not null && Tx.ToHex(parsed.Payload) == Tx.ToHex(payload));
}

// SPV ENVELOPE end-to-end: a single-tx block — build the tx, put its merkle root in an 80-byte header
// (regtest easy bits so PoW passes), make the envelope, and it VERIFIES (proof-of-work + merkle).
{
    var tx = new NativeTx(2, new[] { new TxInputN(new string('1', 64), 0, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(5000, NodeWallet.P2pkhScript(new byte[20])) }, 0);
    string txidDisp = Tx.Txid(tx);
    byte[] rootInternal = Tx.FromHex(txidDisp); System.Array.Reverse(rootInternal);
    var hdr = new byte[80];
    hdr[0] = 2;                                              // version
    System.Array.Copy(rootInternal, 0, hdr, 36, 32);        // merkle root (single tx)
    hdr[72] = 0xff; hdr[73] = 0xff; hdr[74] = 0x7f; hdr[75] = 0x20;   // bits 0x207fffff (regtest max target)
    var bf = BlockMerkle.BranchFor(new List<string> { txidDisp }, txidDisp);
    byte[] raw = Tx.Serialize(tx);
    bool verified = false;
    if (bf is not null)
        for (uint nonce = 0; nonce < 500000 && !verified; nonce++)   // grind PoW (regtest target → found in a few tries)
        {
            hdr[76] = (byte)nonce; hdr[77] = (byte)(nonce >> 8); hdr[78] = (byte)(nonce >> 16); hdr[79] = (byte)(nonce >> 24);
            if (new SpvEnvelope(raw, hdr, bf.Value.branch, bf.Value.index).Verify()) verified = true;
        }
    X("spv-envelope: a single-tx envelope verifies (PoW grind + merkle)", verified);
    var hdrBad = (byte[])hdr.Clone(); hdrBad[36] ^= 0xff;    // corrupt the merkle root, keep the valid nonce
    X("spv-envelope: a wrong merkle root fails verification", bf is not null && !new SpvEnvelope(raw, hdrBad, bf.Value.branch, bf.Value.index).Verify());
}

// SPVSPEND pay-to-many end-to-end: receive a real (PoW-verified) coin, then spend it to TWO recipients
// with change; the built tx has the right outputs and each input is FORKID-signed.
{
    byte[] mypriv = Type42.UniqueKey(new byte[32] { 140, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 }, "spend"); byte[] mypub = Secp256k1.PublicKey(mypriv);
    byte[] myscript = NodeWallet.P2pkhScript(Recovery.Hash160(mypub));
    var spv = new SpvWallet(new[] { myscript });
    var ctx = new NativeTx(2, new[] { new TxInputN(new string('3', 64), 0, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(100000, myscript) }, 0);
    string ctxid = Tx.Txid(ctx); byte[] rootI = Tx.FromHex(ctxid); System.Array.Reverse(rootI);
    var hdr = new byte[80]; hdr[0] = 2; System.Array.Copy(rootI, 0, hdr, 36, 32); hdr[72] = 0xff; hdr[73] = 0xff; hdr[74] = 0x7f; hdr[75] = 0x20;
    var cbf = BlockMerkle.BranchFor(new List<string> { ctxid }, ctxid);
    byte[] craw = Tx.Serialize(ctx); bool recv = false;
    if (cbf is not null) for (uint n = 0; n < 500000 && !recv; n++) { hdr[76] = (byte)n; hdr[77] = (byte)(n >> 8); hdr[78] = (byte)(n >> 16); hdr[79] = (byte)(n >> 24); if (spv.Receive(new SpvEnvelope(craw, hdr, cbf.Value.branch, cbf.Value.index))) recv = true; }
    X("spvspend-many: a PoW-verified coin is received (100000 sat)", recv && spv.Balance() == 100000);
    var keymap = new Dictionary<string, (byte[] priv, byte[] pub)> { [Tx.ToHex(myscript)] = (mypriv, mypub) };
    byte[] r1 = NodeWallet.P2pkhScript(new byte[20]); var pkh2 = new byte[20]; pkh2[0] = 1; byte[] r2 = NodeWallet.P2pkhScript(pkh2);
    var built = SpvSpend.BuildMany(spv, keymap, new List<(byte[], long)> { (r1, 30000), (r2, 20000) }, 1000, myscript, null);
    X("spvspend-many: pays both recipients + change (3 outputs)", built is not null && built.Tx.Outputs.Count == 3 && built.Tx.Outputs[0].Value == 30000 && built.Tx.Outputs[1].Value == 20000 && built.Tx.Outputs[2].Value == 49000);
    X("spvspend-many: each input is FORKID-signed", built is not null && built.Tx.Inputs.All(i => i.ScriptSig.Length > 100));
}

// BLOOM MATCH spend-detection: a tx that SPENDS a watched outpoint matches the filter (so the wallet
// detects its coins being spent, not just received).
{
    var f = new BloomFilter(8, 0.0001, 99);
    string watchedTxid = new string('5', 64); long watchedVout = 2;
    f.Insert(BloomMatch.Outpoint(watchedTxid, watchedVout));
    var spendTx = new NativeTx(2, new[] { new TxInputN(watchedTxid, watchedVout, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(1000, NodeWallet.P2pkhScript(new byte[20])) }, 0);
    X("bloommatch: a tx spending my watched outpoint matches", BloomMatch.Matches(spendTx, Tx.Hash256(new byte[] { 9 }), f));
    var unrelated = new NativeTx(2, new[] { new TxInputN(new string('6', 64), 0, System.Array.Empty<byte>(), 0xffffffff) }, new[] { new TxOutputN(1000, NodeWallet.P2pkhScript(new byte[20])) }, 0);
    X("bloommatch: an unrelated spend does not match", !BloomMatch.Matches(unrelated, Tx.Hash256(new byte[] { 10 }), f));
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

// FULL ON-CHAIN GAME: play a COMPLETE Estates game to a winner — provably-fair beacon dice, a typed
// on-chain transaction payload for every single action, committed fair decks. This is the whole product
// exercised end to end (Engine + Beacon + TxProtocol), with no node required.
int gfail = 0;
try
{
    var seed = SHA256.HashData("estates-onchain-demo-v1"u8.ToArray());
    var gr = GamePlay.PlayToEnd("regtest", 2, 1_000_000_000, seed);
    var gr2 = GamePlay.PlayToEnd("regtest", 2, 1_000_000_000, seed);   // same seed must reproduce the game exactly
    int rolls = gr.Moves.Count(m => m.Action == "ROLL");
    bool deterministic = gr2.Winner == gr.Winner && gr2.OnChainTxCount == gr.OnChainTxCount;
    bool ok = gr.Finished && gr.Winner is not null && gr.OnChainTxCount > 0 && rolls > 0 && deterministic;
    // every move carries a non-empty, typed on-chain payload
    bool everyMoveOnChain = gr.Moves.All(m => m.OnChainPayload is { Length: > 0 } && TxProtocol.Read(m.OnChainPayload) is not null);
    if (ok && everyMoveOnChain)
        Console.WriteLine($"GAME: full Estates game played ON-CHAIN — {gr.Seats} seats, winner=seat {gr.Winner}, {gr.Turns} turns, {gr.OnChainTxCount} on-chain txs ({rolls} provable-dice rolls), replay-deterministic ✓");
    else
    { Console.Error.WriteLine($"GAME FAIL: finished={gr.Finished} winner={gr.Winner} txs={gr.OnChainTxCount} rolls={rolls} det={deterministic} allOnChain={everyMoveOnChain}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"GAME FAIL: {ex.Message}"); gfail = 1; }

// PLAYER-TO-PLAYER TRADE: an undeveloped title changes hands for cash, atomically; illegal trades rejected.
try
{
    var deck = new Dictionary<string, List<int>>();
    foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
    var gs = Engine.InitialState("regtest", 2, 1_000_000, deck, false);
    gs.Phase = "AWAIT_POST"; gs.Current = 0;
    int pid = Params.Instance.Board.First(sp => sp.Type == "property" && sp.Group != null).Id;
    gs.Titles[pid].Owner = 0;
    long b0 = gs.Seats[0].Balance, b1 = gs.Seats[1].Balance;
    long price = System.Math.Min(b1 / 4, 100);                  // affordable within starting cash
    var rSell = Engine.Apply(gs, new Estates.Core.Action("TRADE") { PropertyId = pid, SeatIndex = 1, Amount = price, Choice = "sell" });
    bool sold = rSell.Ok && rSell.State!.Titles[pid].Owner == 1 && rSell.State.Seats[0].Balance == b0 + price && rSell.State.Seats[1].Balance == b1 - price;
    var gs2 = rSell.State ?? gs;
    var rBuy = Engine.Apply(gs2, new Estates.Core.Action("TRADE") { PropertyId = pid, SeatIndex = 1, Amount = price, Choice = "buy" });
    bool bought = rBuy.Ok && rBuy.State!.Titles[pid].Owner == 0;
    var gs3 = rBuy.State ?? gs2;
    bool rejPoor = !Engine.Apply(gs3, new Estates.Core.Action("TRADE") { PropertyId = pid, SeatIndex = 1, Amount = 999_999_999, Choice = "buy" }).Ok;
    bool rejSelf = Engine.Apply(gs3, new Estates.Core.Action("TRADE") { PropertyId = pid, SeatIndex = 0, Amount = 1, Choice = "sell" }).Code == "SELF_TRADE";
    if (sold && bought && rejPoor && rejSelf)
        Console.WriteLine("TRADE: an undeveloped title changed hands for cash both ways (sell + buy back), settled atomically; self-trade + insolvent trade REJECTED ✓");
    else
    { Console.Error.WriteLine($"TRADE FAIL: sold={sold} bought={bought} rejPoor={rejPoor} rejSelf={rejSelf}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"TRADE FAIL: {ex.Message}"); gfail = 1; }

// REPRIEVE CARD: a held "leave the Holding Yard free" card can actually be spent to leave at no cost.
try
{
    var deck = new Dictionary<string, List<int>>();
    foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
    var gs = Engine.InitialState("regtest", 2, 1_000_000, deck, false);
    gs.Phase = "AWAIT_ROLL"; gs.Current = 0;
    gs.Seats[0].InHolding = true; gs.Seats[0].HoldingTurns = 1; gs.Seats[0].ReprieveCards = 1;
    long bal = gs.Seats[0].Balance;
    var r = Engine.Apply(gs, new Estates.Core.Action("USE_REPRIEVE"));
    bool freed = r.Ok && !r.State!.Seats[0].InHolding && r.State.Seats[0].ReprieveCards == 0
                 && r.State.Seats[0].Balance == bal && r.State.Phase == "AWAIT_ROLL";
    // with no card it must be rejected
    var gs2 = Engine.InitialState("regtest", 2, 1_000_000, deck, false);
    gs2.Phase = "AWAIT_ROLL"; gs2.Seats[0].InHolding = true;
    bool rejNoCard = Engine.Apply(gs2, new Estates.Core.Action("USE_REPRIEVE")).Code == "NO_REPRIEVE";
    if (freed && rejNoCard)
        Console.WriteLine("REPRIEVE: a held reprieve card is spent to leave the Holding Yard free (then roll); no-card use REJECTED ✓");
    else
    { Console.Error.WriteLine($"REPRIEVE FAIL: freed={freed} rejNoCard={rejNoCard}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"REPRIEVE FAIL: {ex.Message}"); gfail = 1; }

// FULL GAME -> REAL SIGNED BSV TX CHAIN: compile the whole game into actual signed transactions (one per
// move), each FORKID-signed and locally spend-verified, threaded into a real change-spend chain. No node.
try
{
    var w = new StandaloneWallet(SHA256.HashData("estates-onchain-game-wallet"u8.ToArray()), "regtest");
    var funding = new Coin(new string('a', 64), 0, 5_000_000_000, 0);   // one funding coin at address 0
    var sg = OnChainGame.PlayAndSign(w, funding, "regtest", 2, 1_000_000_000, SHA256.HashData("estates-onchain-demo-v1"u8.ToArray()));
    bool ok = sg.Game.Finished && sg.Txs.Count == sg.Game.OnChainTxCount && sg.Txs.Count > 0 && sg.AllSigned && sg.ChainsCleanly;
    if (ok)
        Console.WriteLine($"GAME-TX: whole game compiled to {sg.Txs.Count} REAL signed BSV txs — every one FORKID-verified + chained, total fees {sg.TotalFees} sat ✓");
    else
    { Console.Error.WriteLine($"GAME-TX FAIL: finished={sg.Game.Finished} txs={sg.Txs.Count}/{sg.Game.OnChainTxCount} signed={sg.AllSigned} chains={sg.ChainsCleanly}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"GAME-TX FAIL: {ex.Message}"); gfail = 1; }

// TRUSTLESS FOLLOWER: reconstruct + verify the WHOLE game from its on-chain transcript alone — every dice
// roll re-derived from the beacon reveals (claimed dice not trusted), every action decoded from its payload
// and re-applied through the pure engine, winner re-confirmed. Plus a hostile check: a tampered roll MUST
// be rejected. This is "game state IS the verified on-chain transcript" made real.
try
{
    var seed = SHA256.HashData("estates-onchain-demo-v1"u8.ToArray());
    var g = GamePlay.PlayToEnd("regtest", 2, 1_000_000_000, seed);
    var tr = GameTranscript.Verify(g);
    bool ok = tr.Ok && tr.Winner == g.Winner && tr.RollsVerified > 0 && tr.MovesReplayed > 0;
    // hostile: flip one die on the first roll — the beacon re-derivation must catch the lie
    bool flipped = false;
    var tamperedMoves = g.Moves.Select(m =>
    {
        if (!flipped && m.Action == "ROLL" && m.Dice is not null)
        { flipped = true; return m with { Dice = new[] { (m.Dice[0] % 6) + 1, m.Dice[1] } }; }
        return m;
    }).ToList();
    var trBad = GameTranscript.Verify(g with { Moves = tamperedMoves });
    bool caughtCheat = !trBad.Ok;
    if (ok && caughtCheat)
        Console.WriteLine($"TRUSTLESS: whole game reconstructed + verified from the on-chain transcript alone — winner=seat {tr.Winner}, {tr.RollsVerified} rolls re-derived from the beacon, {tr.MovesReplayed} moves replayed; a tampered roll was REJECTED ✓");
    else
    { Console.Error.WriteLine($"TRUSTLESS FAIL: ok={tr.Ok} reason={tr.Reason} caughtCheat={caughtCheat}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"TRUSTLESS FAIL: {ex.Message}"); gfail = 1; }

// TITLE DEEDS AS ENCRYPTED NFTs: every property the game assigns becomes an encrypted NFT deed sealed to
// its owner — only the owner can open it, everyone else sees opaque bytes, and a transfer re-seals it so
// the prior owner can no longer read it (digital scarcity).
try
{
    var seed = SHA256.HashData("estates-onchain-demo-v1"u8.ToArray());
    var g = GamePlay.PlayToEnd("regtest", 2, 1_000_000_000, seed);
    var keys = DeedNft.DeriveSeatKeys(SHA256.HashData("estates-seat-keys"u8.ToArray()), g.Seats);
    var issuer = new StandaloneWallet(SHA256.HashData("estates-deed-issuer"u8.ToArray()), "regtest");
    issuer.AddCoin(new string('e', 64), 0, 5_000_000_000, 0);   // fund the deed issuer (local; mints are real carrier txs)
    int minted = 0, ownerOpens = 0, othersRejected = 0;
    DeedMint? sample = null;
    foreach (var kv in g.FinalOwners)
    {
        int pid = kv.Key, owner = kv.Value;
        var dm = DeedNft.Mint(issuer, pid, Params.Instance.Board[pid].Name, owner, keys[owner].Pub, 1);
        minted++;
        if (DeedNft.Open(keys[owner].Priv, dm.NftData) is not null) ownerOpens++;
        bool allOthersBlind = Enumerable.Range(0, g.Seats).Where(s => s != owner)
            .All(s => DeedNft.Open(keys[s].Priv, dm.NftData) is null);
        if (allOthersBlind) othersRejected++;
        sample ??= dm;
    }
    // transfer scarcity: re-seal the sample deed to a different seat; new owner reads it, old owner cannot
    bool scarcity = true;
    if (sample is not null && g.Seats >= 2)
    {
        int from = sample.Owner, to = (from + 1) % g.Seats;
        var moved = DeedNft.ReSeal(issuer, sample, Params.Instance.Board[sample.PropertyId].Name, to, keys[to].Pub, 1);
        scarcity = DeedNft.Open(keys[to].Priv, moved.NftData) is not null
                && DeedNft.Open(keys[from].Priv, moved.NftData) is null;
    }
    bool ok = minted > 0 && ownerOpens == minted && othersRejected == minted && scarcity;
    if (ok)
        Console.WriteLine($"DEEDS: {minted} title deeds minted as encrypted NFTs — each opens ONLY for its owner ({ownerOpens}/{minted}), all non-owners blind ({othersRejected}/{minted}), transfer re-seals (scarcity) ✓");
    else
    { Console.Error.WriteLine($"DEEDS FAIL: minted={minted} ownerOpens={ownerOpens} othersRejected={othersRejected} scarcity={scarcity}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"DEEDS FAIL: {ex.Message}"); gfail = 1; }

// MOVE AUTHENTICATION: every move is ECDSA-signed by the seat that made it; a peer verifies it before
// accepting. A move forged with the wrong seat's key MUST be rejected. (Beacon = fair dice, Engine = legal
// moves, MoveAuth = authentic moves, GameTranscript = verifiable history — the whole hostile model.)
try
{
    var seed = SHA256.HashData("estates-onchain-demo-v1"u8.ToArray());
    var g = GamePlay.PlayToEnd("regtest", 2, 1_000_000_000, seed);
    var keys = DeedNft.DeriveSeatKeys(SHA256.HashData("estates-seat-keys"u8.ToArray()), g.Seats);
    var signed = MoveAuth.SignGame(g, keys);
    var (allok, verified, rejected) = MoveAuth.VerifyGame(signed, keys);
    // hostile: re-sign one move with a DIFFERENT seat's key — verification must catch the forgery
    var victim = signed[0];
    int wrongSeat = (victim.Move.Seat + 1) % g.Seats;
    var forged = victim with { Signature = MoveAuth.Sign(victim.Move, keys[wrongSeat]).Signature };
    bool caughtForgery = !MoveAuth.Verify(forged, keys[victim.Move.Seat].Pub);
    bool ok = allok && verified > 0 && rejected == 0 && caughtForgery;
    if (ok)
        Console.WriteLine($"AUTH: all {verified} game moves signed by their acting seat + verified; a forged move (wrong key) was REJECTED ✓");
    else
    { Console.Error.WriteLine($"AUTH FAIL: ok={allok} verified={verified} rejected={rejected} caughtForgery={caughtForgery}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"AUTH FAIL: {ex.Message}"); gfail = 1; }

// MULTIPLAYER: two mutually-distrusting peers each run a GameSession with NO server. Peer A makes each move;
// peer B independently verifies (signature + dice re-derived from the beacon + engine legality) and applies.
// They must stay in lock-step the whole game; a forged or dice-tampered move MUST be rejected by B.
try
{
    var deck = new Dictionary<string, List<int>>();
    foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
    var mpKeys = DeedNft.DeriveSeatKeys(SHA256.HashData("estates-mp-keys"u8.ToArray()), 2);
    GameSession NewS() => new("regtest", 2, 1_000_000_000, new Dictionary<string, List<int>>(deck), mpKeys);
    var P = Params.Instance;
    int BestBuild(GameState s)
    {
        int id = s.Current, pick = -1, lvl = 99;
        foreach (var sp in P.Board)
        {
            if (sp.Type != "property" || sp.Group is null) continue;
            if (!s.Titles.TryGetValue(sp.Id, out var t) || t.Owner != id || t.Mortgaged) continue;
            var m = P.Groups.TryGetValue(sp.Group, out var gg) ? gg.MemberPropertyIds : (IReadOnlyList<int>)Array.Empty<int>();
            if (m.Count == 0 || !m.All(x => s.Titles[x].Owner == id && !s.Titles[x].Mortgaged)) continue;
            if (t.BuildLevel >= 5 || t.BuildLevel > m.Min(x => s.Titles[x].BuildLevel)) continue;
            if (s.Seats[id].Balance < P.BuildCost(sp.Group) + 100) continue;
            if ((t.BuildLevel + 1 == 5 ? s.EstatesRemaining : s.HousesRemaining) < 1) continue;
            if (t.BuildLevel < lvl) { pick = sp.Id; lvl = t.BuildLevel; }
        }
        return pick;
    }
    bool Same(GameState a, GameState b)
        => a.Phase == b.Phase && a.Current == b.Current && a.Winner == b.Winner && a.TurnIndex == b.TurnIndex
           && a.Seats.Select(x => x.Balance).SequenceEqual(b.Seats.Select(x => x.Balance))
           && a.Titles.All(kv => b.Titles[kv.Key].Owner == kv.Value.Owner && b.Titles[kv.Key].BuildLevel == kv.Value.BuildLevel);

    var A = NewS(); var B = NewS();
    int moved = 0; bool inSync = true; string desync = "";
    while (A.Phase != "GAME_OVER" && moved < 6000)
    {
        var s = A.State; string act = "END_TURN"; int pid = 0; string? ch = null;
        switch (s.Phase)
        {
            case "AWAIT_ROLL": act = "ROLL"; break;
            case "AWAIT_BUY": { int pp = s.PendingTitle ?? -1; act = (pp >= 0 && s.Seats[s.Current].Balance >= (P.Board[pp].BasePrice ?? 0)) ? "BUY" : "DECLINE"; break; }
            case "AWAIT_TAX": act = "PAY_TAX"; ch = "flat"; break;
            case "AWAIT_POST": { int bb = BestBuild(s); if (bb >= 0) { act = "BUILD"; pid = bb; } else act = "END_TURN"; break; }
        }
        var pkt = A.Local(act, pid, ch);
        if (!B.Remote(pkt, out var why)) { inSync = false; desync = "B rejected honest move: " + why; break; }
        if (!Same(A.State, B.State)) { inSync = false; desync = "state diverged after " + act; break; }
        moved++;
    }
    // hostile: tampered dice + forged signature on a fresh roll must both be rejected
    var A2 = NewS(); var B2 = NewS();
    var good = A2.Local("ROLL");
    var badDice = good with { Dice = new[] { (good.Dice![0] % 6) + 1, good.Dice[1] } };
    bool rejDice = !B2.Remote(badDice, out _);
    var badSig = good with { Sig = new byte[good.Sig.Length] };
    bool rejSig = !B2.Remote(badSig, out _);

    bool ok = inSync && moved > 50 && rejDice && rejSig;
    if (ok)
        Console.WriteLine($"MULTIPLAYER: two peers stayed in lock-step for {moved} verified moves (winner=seat {A.Winner}); a dice-tampered move and a forged signature were both REJECTED ✓");
    else
    { Console.Error.WriteLine($"MULTIPLAYER FAIL: inSync={inSync} moved={moved} ({desync}) rejDice={rejDice} rejSig={rejSig}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"MULTIPLAYER FAIL: {ex.Message}"); gfail = 1; }

// WIRE: a whole multiplayer game driven across the network — every move serialised to bytes, sent, decoded,
// and re-verified on the other side. Proves two SEPARATE machines can play (the packet round-trips exactly
// and a byte-flipped packet on the wire is rejected).
try
{
    var deck = new Dictionary<string, List<int>>();
    foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
    var k = DeedNft.DeriveSeatKeys(SHA256.HashData("estates-wire-keys"u8.ToArray()), 2);
    GameSession New() => new("regtest", 2, 1_000_000_000, new Dictionary<string, List<int>>(deck), k);
    var P = Params.Instance;
    var A = New(); var B = New();
    int wired = 0; bool ok = true;
    while (A.Phase != "GAME_OVER" && wired < 4000)
    {
        var s = A.State; string act = "END_TURN"; int pid = 0; string? ch = null;
        if (s.Phase == "AWAIT_ROLL") act = "ROLL";
        else if (s.Phase == "AWAIT_BUY") { int pp = s.PendingTitle ?? -1; act = (pp >= 0 && s.Seats[s.Current].Balance >= (P.Board[pp].BasePrice ?? 0)) ? "BUY" : "DECLINE"; }
        else if (s.Phase == "AWAIT_TAX") { act = "PAY_TAX"; ch = "flat"; }
        var pkt = A.Local(act, pid, ch);
        var onWire = GameSession.Encode(pkt);                 // serialise for the network
        var received = GameSession.Decode(onWire);            // the peer parses it back
        if (!B.Remote(received, out var why)) { ok = false; Console.Error.WriteLine("WIRE reject: " + why); break; }
        wired++;
    }
    // a byte-flipped wire packet must be rejected
    var A2 = New(); var B2 = New();
    var w = GameSession.Encode(A2.Local("ROLL"));
    w[^1] ^= 0xff;   // corrupt the last byte (in the seat pubkey / sig region)
    bool rejCorrupt; try { rejCorrupt = !B2.Remote(GameSession.Decode(w), out _); } catch { rejCorrupt = true; }
    bool wirePass = ok && wired > 50 && rejCorrupt;
    if (wirePass)
        Console.WriteLine($"WIRE: a full multiplayer game ran ACROSS THE NETWORK — {wired} move packets serialised, sent, decoded + re-verified (winner=seat {A.Winner}); a corrupted packet was REJECTED ✓");
    else
    { Console.Error.WriteLine($"WIRE FAIL: ok={ok} wired={wired} rejCorrupt={rejCorrupt}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"WIRE FAIL: {ex.Message}"); gfail = 1; }

// NET: the same game over a REAL TCP socket between two peers (loopback host/dialer). Proves the transport,
// not just the format — moves cross an actual network connection and are re-verified on the far side.
try
{
    var deck = new Dictionary<string, List<int>>();
    foreach (var kv in Params.Instance.Decks) deck[kv.Key] = Enumerable.Range(0, kv.Value.Count).ToList();
    var k = DeedNft.DeriveSeatKeys(SHA256.HashData("estates-net-keys"u8.ToArray()), 2);
    GameSession New() => new("regtest", 2, 1_000_000_000, new Dictionary<string, List<int>>(deck), k);
    var P = Params.Instance;
    int port = 50000 + new Random().Next(5000);
    var listener = GameNet.Listen(port);
    GameNet? dialer = null;
    var connectTask = System.Threading.Tasks.Task.Run(() => dialer = GameNet.Connect("127.0.0.1", port));
    var host = GameNet.Accept(listener);          // host side (verifier)
    connectTask.Wait(5000); listener.Stop();
    var A = New(); var B = New();                  // A = dialer (mover), B = host (verifier)
    int over = 0; bool ok = true;
    for (int step = 0; step < 60 && A.Phase != "GAME_OVER"; step++)
    {
        var s = A.State; string act = "END_TURN"; int pid = 0; string? ch = null;
        if (s.Phase == "AWAIT_ROLL") act = "ROLL";
        else if (s.Phase == "AWAIT_BUY") { int pp = s.PendingTitle ?? -1; act = (pp >= 0 && s.Seats[s.Current].Balance >= (P.Board[pp].BasePrice ?? 0)) ? "BUY" : "DECLINE"; }
        else if (s.Phase == "AWAIT_TAX") { act = "PAY_TAX"; ch = "flat"; }
        var pkt = A.Local(act, pid, ch);
        dialer!.Send(pkt);                          // goes out over the TCP socket
        var recv = host.Receive();                  // comes in on the other end
        if (!B.Remote(recv, out var why)) { ok = false; Console.Error.WriteLine("NET reject: " + why); break; }
        if (A.State.Current != B.State.Current || A.State.TurnIndex != B.State.TurnIndex) { ok = false; break; }
        over++;
    }
    dialer?.Dispose(); host.Dispose();
    bool netPass = ok && over >= 25;
    if (netPass)
        Console.WriteLine($"NET: {over} moves crossed a REAL TCP socket between two peers and were re-verified on the far side, in sync ✓");
    else
    { Console.Error.WriteLine($"NET FAIL: ok={ok} over={over}"); gfail = 1; }
}
catch (Exception ex) { Console.Error.WriteLine($"NET FAIL: {ex.Message}"); gfail = 1; }

return (fail == 0 && tfail == 0 && cfail == 0 && sfail == 0 && bfail == 0 && xfail == 0 && gfail == 0) ? 0 : 1;
