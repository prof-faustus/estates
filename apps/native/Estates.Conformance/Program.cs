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

return (fail == 0 && kfail == 0 && tfail == 0) ? 0 : 1;
