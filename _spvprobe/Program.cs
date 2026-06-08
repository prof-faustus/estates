using System.Net.Http;
using System.Text.Json;
using Estates.Core;

string txid="e91f53f0c7f9b6b2f29aa9012a0cd8792a581662cdd0df95a85c47e8d1f3e50e";
using var http=new HttpClient(); http.Timeout=TimeSpan.FromSeconds(20);
string baseUrl="https://api.whatsonchain.com/v1/bsv/main";

string rawhex=(await http.GetStringAsync($"{baseUrl}/tx/{txid}/hex")).Trim();
Console.WriteLine($"rawtx {rawhex.Length/2} bytes");

await Task.Delay(3000);
var tsc=JsonDocument.Parse(await http.GetStringAsync($"{baseUrl}/tx/{txid}/proof/tsc")).RootElement[0];
long index=tsc.GetProperty("index").GetInt64();
string blockhash=tsc.GetProperty("target").GetString()!;
var nodes=new List<string>(); foreach(var n in tsc.GetProperty("nodes").EnumerateArray()) nodes.Add(n.GetString()!);
Console.WriteLine($"index={index} block={blockhash} nodes={nodes.Count}");

await Task.Delay(3000);
var hj=JsonDocument.Parse(await http.GetStringAsync($"{baseUrl}/block/{blockhash}/header")).RootElement;
int ver=hj.GetProperty("version").GetInt32();
string prev=hj.GetProperty("previousblockhash").GetString()!;
string mroot=hj.GetProperty("merkleroot").GetString()!;
long time=hj.GetProperty("time").GetInt64();
string bitsS=hj.GetProperty("bits").GetString()!;
long nonce=hj.GetProperty("nonce").GetInt64();
Console.WriteLine($"hdr ver={ver} time={time} bits={bitsS} nonce={nonce}");

byte[] LE(long v,int n){var b=new byte[n];for(int i=0;i<n;i++)b[i]=(byte)(v>>(8*i));return b;}
byte[] RevHex(string h){var b=Tx.FromHex(h);Array.Reverse(b);return b;}
uint bits=Convert.ToUInt32(bitsS,16);
var hdr=new List<byte>();
hdr.AddRange(LE(ver,4)); hdr.AddRange(RevHex(prev)); hdr.AddRange(RevHex(mroot));
hdr.AddRange(LE(time,4)); hdr.AddRange(LE(bits,4)); hdr.AddRange(LE(nonce,4));
byte[] header80=hdr.ToArray();
Console.WriteLine($"header80 {header80.Length} bytes = {Tx.ToHex(header80)}");

var parsed=BsvHeaders.Parse(header80);
Console.WriteLine($"parsed header ok={parsed!=null}  (block {blockhash})");
Console.WriteLine($"PoW ok = {(parsed!=null && BsvHeaders.MeetsProofOfWork(parsed))}");

var env=new SpvEnvelope(Tx.FromHex(rawhex), header80, nodes, index);
Console.WriteLine($"\n*** ENVELOPE Verify() = {env.Verify()} ***  txid={env.Txid()}");
// show outputs/addresses so we can see who it pays
var tx=Tx.Parse(Tx.FromHex(rawhex))!;
for(int i=0;i<tx.Outputs.Count;i++){
  var sc=tx.Outputs[i].Script;
  string addr="(non-p2pkh)";
  if(sc.Length==25 && sc[0]==0x76 && sc[1]==0xa9 && sc[2]==0x14) addr=Address.P2pkh(sc[3..23], BsvNet.Mainnet);
  Console.WriteLine($"  out[{i}] {tx.Outputs[i].Value} sat -> {addr}");
}
