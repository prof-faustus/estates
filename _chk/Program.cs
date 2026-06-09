using System.Text.Json;
using Estates.Core;

var rpc = new BsvRpc("127.0.0.1", 18443, "e", "e");
async Task<JsonElement?> Call(string m, params object[] p) => await rpc.CallAsync(m, p);

// 0. sanity
var hc = await Call("getblockcount");
Console.WriteLine($"regtest height = {hc}");
string dest = "1DPG6kWbyVaN9T9E6gM7uQCD9SFK8tV5yd";

// 1. ensure the node wallet has spendable coins
var mineAddr = (await Call("getnewaddress"))?.GetString() ?? throw new Exception("no node addr");
await Call("generatetoaddress", 101, mineAddr);

// 2. our wallet (fixed seed), address index 1
byte[] seed = Enumerable.Range(0,32).Select(i=>(byte)(i+7)).ToArray();
var sw = new StandaloneWallet(seed, "regtest");
string myAddr = sw.AddressAt(1);
byte[] myScript = Recovery.P2pkh(Recovery.Hash160(sw.ChildPub(1)));
Console.WriteLine($"my wallet addr = {myAddr}");

// 3. fund our address, mine it in
var ftx = await Call("sendtoaddress", myAddr, 1.0);
Console.WriteLine($"funding txid = {ftx}");
await Call("generatetoaddress", 1, mineAddr);

// 4. SPV-sync the coin (pull proof from node, verify locally, credit)
var spv = new SpvWallet(new[]{ myScript });
int n = await SpvSync.SyncAddressAsync(rpc, spv, myAddr);
Console.WriteLine($"SPV synced {n} coin(s), spv balance = {spv.Balance()} sat");
if (spv.Balance() == 0) { Console.WriteLine("FAIL: no spendable coin"); return; }

// 5. BUILD + SIGN a send to 1DPG... (pay its hash160)
byte[]? destPkh = Base58.CheckDecode(dest, out _);
byte[] destScript = NodeWallet.P2pkhScript(destPkh!);
var keymap = new Dictionary<string,(byte[],byte[])>{ { Tx.ToHex(myScript), (sw.ChildPriv(1), sw.ChildPub(1)) } };
byte[] change = NodeWallet.P2pkhScript(Recovery.Hash160(sw.ChildPub(2)));
long sendAmt = 50_000_000;
var built = SpvSpend.Build(spv, keymap, destScript, sendAmt, 1000, change);
if (built is null) { Console.WriteLine("FAIL: build returned null"); return; }
Console.WriteLine($"built+signed tx {built.Txid}  ({built.Raw.Length} bytes)");

// 6. BROADCAST — the node validates EVERY signature; rejects if signing is wrong
var br = await Call("sendrawtransaction", Tx.ToHex(built.Raw));
Console.WriteLine($"sendrawtransaction -> {br}");
if (br is null) { Console.WriteLine("FAIL: node REJECTED the tx (bad signature/format)"); return; }

// 7. mine it
await Call("generatetoaddress", 1, mineAddr);

// 8. read it back FROM THE CHAIN
var got = await Call("getrawtransaction", built.Txid, true);
if (got is null) { Console.WriteLine("FAIL: tx not found on chain"); return; }
var g = got.Value;
string blockhash = g.TryGetProperty("blockhash", out var bh) ? bh.GetString()! : "(none)";
int confs = g.TryGetProperty("confirmations", out var cf) ? cf.GetInt32() : 0;
Console.WriteLine($"\n*** ON CHAIN: txid {built.Txid}");
Console.WriteLine($"    block {blockhash}   confirmations {confs}");
foreach (var vout in g.GetProperty("vout").EnumerateArray())
{
    long sats = (long)Math.Round(vout.GetProperty("value").GetDouble()*100_000_000);
    var spk = vout.GetProperty("scriptPubKey");
    string addrs = spk.TryGetProperty("addresses", out var aa) && aa.GetArrayLength()>0 ? aa[0].GetString()! :
                   (spk.TryGetProperty("address", out var a1) ? a1.GetString()! : "?");
    string hexpk = spk.GetProperty("hex").GetString()!;
    bool isDest = hexpk == Tx.ToHex(destScript);
    Console.WriteLine($"    vout {sats,12:n0} sat  hash160-match-1DPG={isDest}  ({addrs})");
}
