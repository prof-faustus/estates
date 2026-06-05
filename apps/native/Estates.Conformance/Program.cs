// Estates.Conformance — proves the NATIVE C# engine port is byte-for-byte
// identical to the audited TypeScript reference. Loads the SAME vector file
// (state, action -> expected {ok, stateHash|code}) the TS conformance suite uses,
// applies each through the native Engine, and asserts the native state hash equals
// the expected hash (or the rejection matches). Any divergence fails the build.
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
if (fail == 0) Console.WriteLine("PASS: the native C# engine is byte-for-byte identical to the audited TypeScript reference.");
else Console.Error.WriteLine("FAIL: the native engine DIVERGES from the reference.");

// ---- KEY-LIFECYCLE cross-validation: the native KeyLife must agree with the TS
// reference on every manifest verdict (a TS-signed manifest verifies in C#). ----
int kpass = 0, kfail = 0;
string klPath = Path.Combine(AppContext.BaseDirectory, "keylife-vectors.json");
if (File.Exists(klPath))
{
    using var kdoc = JsonDocument.Parse(File.ReadAllText(klPath));
    var kr = kdoc.RootElement;
    foreach (var v in kr.GetProperty("single").EnumerateArray())
    {
        string name = v.GetProperty("name").GetString()!;
        bool expect = v.GetProperty("expectVerify").GetBoolean();
        var m = KeyLife.Parse(v.GetProperty("manifest"));
        bool got = KeyLife.VerifyManifest(m).Ok;
        if (got == expect) kpass++;
        else { Console.Error.WriteLine($"  [KEYLIFE FAIL] verifyManifest {name}: want {expect}, got {got}"); kfail++; }
    }
    foreach (var v in kr.GetProperty("crossGame").EnumerateArray())
    {
        string name = v.GetProperty("name").GetString()!;
        bool expect = v.GetProperty("expectNoReuse").GetBoolean();
        var ms = v.GetProperty("manifests").EnumerateArray().Select(KeyLife.Parse).ToList();
        bool got = KeyLife.VerifyNoCrossGameReuse(ms).Ok;
        if (got == expect) kpass++;
        else { Console.Error.WriteLine($"  [KEYLIFE FAIL] noCrossGameReuse {name}: want {expect}, got {got}"); kfail++; }
    }
    Console.WriteLine($"Estates.Conformance (keylife): {kpass} passed, {kfail} failed");
    if (kfail == 0) Console.WriteLine("PASS: native KeyLife agrees with the TS reference (TS-signed manifests verify in C#).");
}

// ---- TX cross-validation: native serialize + txid must equal the TS reference ----
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
    if (tfail == 0) Console.WriteLine("PASS: native Tx serialization + txid are byte-for-byte the TS reference.");
}

// ---- CARDNFT cross-validation: native card NFT output script + transfer tx must
// equal the TS reference, and native verify accepts the true move / rejects a copy. -
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
    if (cfail == 0) Console.WriteLine("PASS: native card NFT output + transfer tx are byte-for-byte the TS reference; true move accepted, copy rejected.");
}

// ---- SCRIPTVM cross-validation: native BIP-143 sighash + ECDSA OP_CHECKSIG must
// equal the TS reference (a TS-signed input verifies; a tampered one fails). ----
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
    Check("valid signature verifies (ECDSA OP_CHECKSIG)", Scriptvm.CheckSig(tx, idx, prevoutScript, prevoutValue, Tx.FromHex(v.GetProperty("validSig").GetString()!), pub));
    Check("tampered signature is rejected", !Scriptvm.CheckSig(tx, idx, prevoutScript, prevoutValue, Tx.FromHex(v.GetProperty("tamperedSig").GetString()!), pub));

    Console.WriteLine($"Estates.Conformance (scriptvm): {spass} passed, {sfail} failed");
    if (sfail == 0) Console.WriteLine("PASS: native BIP-143 sighash + secp256k1 ECDSA verify match the TS reference.");
}

// ---- SIGN cross-validation: native per-game key derivation (HKDF->Ed25519) must
// equal the TS reference (same master+gameId -> same signPub), and Ed25519 sign/
// verify round-trips + verifies a TS-made signature. ----
int gpass = 0, gfail = 0;
string sgPath = Path.Combine(AppContext.BaseDirectory, "sign-vectors.json");
if (File.Exists(sgPath))
{
    using var gdoc = JsonDocument.Parse(File.ReadAllText(sgPath));
    var root2 = gdoc.RootElement;
    foreach (var d in root2.GetProperty("derivations").EnumerateArray())
    {
        byte[] master = Tx.FromHex(d.GetProperty("master").GetString()!);
        var gid = d.GetProperty("gameId");
        string? gameId = gid.ValueKind == JsonValueKind.Null ? null : gid.GetString();
        string got = Tx.ToHex(Sign.SigningKeyFromMaster(master, gameId).Pub);
        if (got == d.GetProperty("expectedSignPub").GetString()) gpass++;
        else { Console.Error.WriteLine($"  [SIGN FAIL] derive(master,{gameId ?? "—"}): signPub mismatch"); gfail++; }
    }
    var sg = root2.GetProperty("signature");
    byte[] msg = Tx.FromHex(sg.GetProperty("message").GetString()!);
    byte[] tsSig = Tx.FromHex(sg.GetProperty("sig").GetString()!);
    byte[] signPub = Tx.FromHex(sg.GetProperty("signPub").GetString()!);
    void Ck(string what, bool ok) { if (ok) gpass++; else { Console.Error.WriteLine($"  [SIGN FAIL] {what}"); gfail++; } }
    Ck("native verifies a TS-made Ed25519 signature", Sign.VerifyData(msg, tsSig, signPub));
    // native sign -> TS-compatible verify (round-trip with a freshly derived key)
    var (priv, pub) = Sign.SigningKeyFromMaster(Tx.FromHex("11".PadRight(64, '1')), "c3".PadLeft(64, 'c'));
    Ck("native Ed25519 sign verifies", Sign.VerifyData(msg, Sign.SignData(msg, priv), pub));
    Ck("native rejects a tampered Ed25519 signature", !Sign.VerifyData(msg, tsSig.Select((b, i) => i == 5 ? (byte)(b ^ 0xff) : b).ToArray(), signPub));

    Console.WriteLine($"Estates.Conformance (sign): {gpass} passed, {gfail} failed");
    if (gfail == 0) Console.WriteLine("PASS: native key derivation + Ed25519 match the TS reference (native player identity == web).");
}

// ---- FRAMES cross-validation: native re-derives the canonical signedBytes for
// EVERY message kind and verifies the web signature (the replay's auth layer). ----
int fpass = 0, ffail = 0;
string frPath = Path.Combine(AppContext.BaseDirectory, "frames-vectors.json");
if (File.Exists(frPath))
{
    using var fdoc = JsonDocument.Parse(File.ReadAllText(frPath));
    foreach (var v in fdoc.RootElement.EnumerateArray())
    {
        string kind = v.GetProperty("kind").GetString()!;
        var msg = v.GetProperty("msg");
        string signPub = v.GetProperty("signPub").GetString()!;
        bool bytesOk = Tx.ToHex(TableMsg.SignedBytes(msg, signPub)) == v.GetProperty("signedBytes").GetString();
        bool verifyOk = TableMsg.VerifyFrame(msg, signPub, Tx.FromHex(v.GetProperty("sig").GetString()!));
        if (bytesOk && verifyOk) fpass++;
        else { Console.Error.WriteLine($"  [FRAMES FAIL] {kind}: bytes={bytesOk} verify={verifyOk}"); ffail++; }
    }
    Console.WriteLine($"Estates.Conformance (frames): {fpass} passed, {ffail} failed");
    if (ffail == 0) Console.WriteLine("PASS: native re-derives signedBytes + verifies EVERY table message kind.");
}

// ---- TABLEMSG cross-validation: native re-derives the canonical signed-frame
// bytes for a gameplay message and verifies the web's signature (so a native
// client can authenticate the SAME table frames). ----
int mpass = 0, mfail = 0;
string tmPath = Path.Combine(AppContext.BaseDirectory, "tablemsg-vectors.json");
if (File.Exists(tmPath))
{
    using var mdoc = JsonDocument.Parse(File.ReadAllText(tmPath));
    foreach (var v in mdoc.RootElement.EnumerateArray())
    {
        string name = v.GetProperty("name").GetString()!;
        var action = StateJson.ParseAction(v.GetProperty("action"));
        string signPub = v.GetProperty("signPub").GetString()!;
        string gotBytes = Tx.ToHex(TableMsg.SignedBytesForAction(action, signPub));
        bool bytesOk = gotBytes == v.GetProperty("signedBytes").GetString();
        bool verifyOk = TableMsg.VerifyActionFrame(action, signPub, Tx.FromHex(v.GetProperty("sig").GetString()!));
        if (bytesOk && verifyOk) mpass++;
        else { Console.Error.WriteLine($"  [TABLEMSG FAIL] {name}: bytes={bytesOk} verify={verifyOk}"); mfail++; }
    }
    Console.WriteLine($"Estates.Conformance (tablemsg): {mpass} passed, {mfail} failed");
    if (mfail == 0) Console.WriteLine("PASS: native re-derives the canonical signed-frame bytes + verifies web table messages.");
}

// ---- REPLAY cross-validation: the native rebuild must replay a REAL game's
// ordered relay log into the SAME canonical state hash as the web NetTable. ----
int repfail = 0;
string repPath = Path.Combine(AppContext.BaseDirectory, "replay-vectors.json");
if (File.Exists(repPath))
{
    using var rdoc = JsonDocument.Parse(File.ReadAllText(repPath));
    var rv = rdoc.RootElement;
    var log = rv.GetProperty("log").EnumerateArray().Select(x => x.GetString()!).ToList();
    string? rgid = rv.TryGetProperty("gameId", out var rg) ? rg.GetString() : null;
    string? got = GameReplay.ReplayStateHash(log, rgid);
    string want = rv.GetProperty("stateHash").GetString()!;
    bool ok = got == want;
    Console.WriteLine($"Estates.Conformance (replay): {(ok ? $"PASS — native replayed {log.Count} frames (turn {rv.GetProperty("turnIndex").GetInt32()}) to the SAME state hash as the web" : $"FAIL — want {want[..16]}… got {got?[..16] ?? "null"}…")}");
    if (!ok) repfail = 1;
}

// ---- DEALERLESS DECK SHUFFLE replay: a game that ran the entropy round must
// replay to the SAME jointly-generated deckOrder + canonical hash. Proves Deck.cs
// (combineSeedBound / permutation / dealerlessDeckOrder) + GameReplay's dcommit/
// dreveal path agree with the web byte-for-byte. ----
int drfail = 0;
string drPath = Path.Combine(AppContext.BaseDirectory, "deckreplay-vectors.json");
if (File.Exists(drPath))
{
    using var ddoc = JsonDocument.Parse(File.ReadAllText(drPath));
    var dv = ddoc.RootElement;
    var dlog = dv.GetProperty("log").EnumerateArray().Select(x => x.GetString()!).ToList();
    string dgid = dv.GetProperty("gameId").GetString()!;
    var dstate = GameReplay.ReplayState(dlog, dgid);
    string? dgot = dstate == null ? null : Canonical.HashState(dstate);
    string dwant = dv.GetProperty("stateHash").GetString()!;
    // direct check: the recomputed deckOrder must equal the web's, deck by deck.
    bool orderOk = dstate?.DeckOrder != null;
    foreach (var deck in dv.GetProperty("deckOrder").EnumerateObject())
    {
        var wantArr = deck.Value.EnumerateArray().Select(x => x.GetInt32()).ToList();
        var gotArr = dstate?.DeckOrder?.GetValueOrDefault(deck.Name);
        if (gotArr == null || !gotArr.SequenceEqual(wantArr)) orderOk = false;
    }
    bool dok = dgot == dwant && orderOk;
    Console.WriteLine($"Estates.Conformance (deckshuffle): {(dok ? $"PASS — native recomputed the jointly-generated deck order [{string.Join(", ", dstate!.DeckOrder!.Keys)}] and replayed {dlog.Count} frames to the SAME hash as the web" : $"FAIL — orderOk {orderOk}, want {dwant[..16]}… got {dgot?[..16] ?? "null"}…")}");
    if (!dok) drfail = 1;
}
else Console.WriteLine("Estates.Conformance (deckshuffle): skipped (no deckreplay-vectors.json)");

// ---- BEACON cross-validation: native dice beacon (commit/reveal -> dice + chained
// beacon) must equal the TS reference; a non-opening reveal is rejected. ----
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
    if (bfail == 0) Console.WriteLine("PASS: native dice beacon (dice + chained beacon + reveal checks) matches the TS reference.");
}

// ---- RELAY live round-trip (optional): if the relay is running, the native
// client publishes a frame + reads it back from the ordered log. Skipped (not a
// failure) when the relay is down, so the offline conformance run never depends on it.
int rfail = 0;
var relay = new RelayClient();
if (await relay.ReachableAsync())
{
    string ch = "native-relay-test-" + Guid.NewGuid().ToString("N")[..8];
    byte[] frame = System.Text.Encoding.UTF8.GetBytes("{\"native\":\"hello\",\"n\":42}");
    await relay.PublishAsync(ch, frame);
    var hist = await relay.HistoryAsync(ch);
    bool ok = hist.Any(f => Tx.ToHex(f) == Tx.ToHex(frame));
    Console.WriteLine($"Estates.Conformance (relay): live round-trip {(ok ? "PASS — native client published + read back its frame" : "FAIL")}");
    if (!ok) rfail = 1;
}
else Console.WriteLine("Estates.Conformance (relay): skipped (relay not running on 127.0.0.1:8788)");

// ---- LIVE SPECTATE end-to-end: if tools/live-spectate.ts has published a REAL
// game to a live HTTP relay (manifest on disk), the native client reads that
// channel back over HTTP and replays it with GameReplay — and must reach the SAME
// canonical state hash the web NetTable produced. This is the native spectate path
// exercised over the real wire, not just a static vector. Skipped when absent.
int lfail = 0;
// the harness writes the manifest to the project dir at RUNTIME (after build), so
// the runner points ESTATES_LIVE_SPECTATE at it; fall back to the output dir.
string livePath = Environment.GetEnvironmentVariable("ESTATES_LIVE_SPECTATE")
    ?? Path.Combine(AppContext.BaseDirectory, "live-spectate.json");
if (File.Exists(livePath))
{
    using var ldoc = JsonDocument.Parse(File.ReadAllText(livePath));
    var lm = ldoc.RootElement;
    string lurl = lm.GetProperty("relayUrl").GetString()!;
    string lch = lm.GetProperty("channel").GetString()!;
    string lwant = lm.GetProperty("stateHash").GetString()!;
    int lframes = lm.GetProperty("frames").GetInt32();
    var lclient = new RelayClient(lurl);
    if (await lclient.ReachableAsync())
    {
        var lhist = await lclient.HistoryAsync(lch);
        var lhex = lhist.Select(f => Tx.ToHex(f)).ToList();
        string? lgid = lm.TryGetProperty("gameId", out var lg) ? lg.GetString() : null;
        string? lgot = GameReplay.ReplayStateHash(lhex, lgid);
        bool lok = lhist.Count == lframes && lgot == lwant;
        Console.WriteLine($"Estates.Conformance (spectate): {(lok ? $"PASS — native read {lhist.Count} frames live over HTTP from '{lch}' and replayed to the SAME hash as the web ({lwant[..16]}…)" : $"FAIL — frames {lhist.Count}/{lframes}, want {lwant[..16]}… got {lgot?[..16] ?? "null"}…")}");
        if (!lok) lfail = 1;
    }
    else Console.WriteLine($"Estates.Conformance (spectate): skipped (live relay {lurl} not reachable)");
}
else Console.WriteLine("Estates.Conformance (spectate): skipped (no live-spectate.json; run tools/live-spectate.ts alongside)");

return (fail == 0 && kfail == 0 && tfail == 0 && cfail == 0 && sfail == 0 && gfail == 0 && mfail == 0 && bfail == 0 && ffail == 0 && repfail == 0 && drfail == 0 && rfail == 0 && lfail == 0) ? 0 : 1;
