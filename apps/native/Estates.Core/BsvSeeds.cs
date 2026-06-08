// Estates.Core/BsvSeeds.cs — how an SPV wallet FINDS public BSV nodes on the live network, so it never
// depends on any single (or local) node. These are the public DNS seeds the BSV network publishes; each
// resolves to a rotating set of reachable full-node IPs. The wallet resolves a seed, gets a handful of
// peer IPs, and opens BsvPeer links to them for headers + merkle proofs. Same shape for every network
// (only the seed list + default port differ — a config tag, never a code branch).
//
// WHY DNS seeds (not a hardcoded IP): a single pinned IP is a single point of failure and a censorship
// chokepoint. DNS seeds return many live nodes, rotated by the seed operators, so the wallet always finds
// a peer that is AT THE TIP — which is the whole point: the wallet's truth is the live network, not me.
using System.Net;
using System.Net.Sockets;

namespace Estates.Core;

public static class BsvSeeds
{
    // Public DNS seeds the BSV network operators publish. Resolving any one yields live node IPs.
    public static IReadOnlyList<string> DnsSeeds(BsvNet net) => net switch
    {
        BsvNet.Mainnet => new[] { "seed.bitcoinsv.io", "seed.cascharia.com", "seed.satoshisvision.network" },
        BsvNet.Testnet => new[] { "testnet-seed.bitcoinsv.io", "testnet-seed.cascharia.com" },
        _ => Array.Empty<string>(),   // regtest: peers are local/explicit, no public seeds
    };

    /// <summary>Resolve the DNS seeds to a de-duplicated list of public node IPs (IPv4) on the default
    /// port. Best-effort and total: a seed that fails to resolve is skipped, never throws. Returns at most
    /// <paramref name="max"/> endpoints.</summary>
    public static List<(string host, int port)> Discover(BsvNet net, int max = 12, int perSeedTimeoutMs = 4000)
    {
        var found = new List<(string, int)>();
        var seen = new HashSet<string>();
        int port = BsvWire.DefaultPort(net);
        foreach (var seed in DnsSeeds(net))
        {
            if (found.Count >= max) break;
            try
            {
                var task = Dns.GetHostAddressesAsync(seed);
                if (!task.Wait(perSeedTimeoutMs)) continue;     // skip a slow seed; never block the wallet
                foreach (var a in task.Result)
                {
                    if (a.AddressFamily != AddressFamily.InterNetwork) continue;   // IPv4 only (NetAddr is ipv4-mapped)
                    string ip = a.ToString();
                    if (seen.Add(ip)) found.Add((ip, port));
                    if (found.Count >= max) break;
                }
            }
            catch { /* total: a dead seed is just skipped */ }
        }
        return found;
    }
}
