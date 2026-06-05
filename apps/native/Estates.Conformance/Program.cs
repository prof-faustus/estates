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

Console.WriteLine($"\nEstates.Conformance: {pass} passed, {fail} failed of {pass + fail} vectors");
if (fail == 0) Console.WriteLine("PASS: the native C# engine is byte-for-byte identical to the audited TypeScript reference.");
else Console.Error.WriteLine("FAIL: the native engine DIVERGES from the reference.");
return fail == 0 ? 0 : 1;
