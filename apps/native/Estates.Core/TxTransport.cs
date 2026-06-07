// Estates.Core/TxTransport.cs — DUAL-PROPAGATION transport, the rule end-to-end: a message-transaction
// is sent BOTH directly IP-to-IP to the other player(s) AND broadcast to the mining nodes (on-chain).
// There is no raw non-transaction packet and no block-scanning for the player path — the transaction
// arrives directly over IP, and the miners receive it for inclusion on the chain. On receive, incoming
// bytes are parsed as a transaction and the encrypted carrier output (TxMessage) is extracted/opened.
using System.Threading.Tasks;

namespace Estates.Core;

public static class TxTransport
{
    /// <summary>The 1-sat carrier output script for a sealed message (spendable by owner; no OP_RETURN).</summary>
    public static byte[] MessageOutput(byte[] carrier, byte[] ownerPkh) => OnChainActions.CarrierScript(carrier, ownerPkh);

    /// <summary>Read the leading pushdata (the ESTATES carrier) out of a carrier output script. TOTAL —
    /// null if the script does not begin with a single data push.</summary>
    public static byte[]? ReadCarrier(byte[] script)
    {
        if (script is null || script.Length < 1) return null;
        int p = 0; byte op = script[p++];
        long len;
        if (op >= 0x01 && op <= 0x4b) len = op;
        else if (op == 0x4c) { if (p + 1 > script.Length) return null; len = script[p++]; }
        else if (op == 0x4d) { if (p + 2 > script.Length) return null; len = script[p] | (script[p + 1] << 8); p += 2; }
        else if (op == 0x4e) { if (p + 4 > script.Length) return null; len = (uint)(script[p] | (script[p + 1] << 8) | (script[p + 2] << 16) | (script[p + 3] << 24)); p += 4; }
        else return null;
        if (len < 1 || p + len > script.Length) return null;
        var data = new byte[len]; System.Array.Copy(script, p, data, 0, (int)len); return data;
    }

    /// <summary>Scan a received transaction's outputs for an ESTATES message addressed to us, and open
    /// it with our private key. null if none of the outputs is a message we can open.</summary>
    public static (TxType type, byte[] senderMsgPub, byte[] plaintext)? Extract(NativeTx tx, byte[] recipientPriv)
    {
        foreach (var o in tx.Outputs)
        {
            var carrier = ReadCarrier(o.Script);
            if (carrier is null) continue;
            var m = TxMessage.OpenCarrier(carrier, recipientPriv);
            if (m is not null) return m;
        }
        return null;
    }

    /// <summary>THE RULE: send the raw transaction directly IP-to-IP to every connected player AND
    /// broadcast it to the mining nodes (on-chain). Returns true if a miner accepted it.</summary>
    public static async Task<bool> SendAsync(P2PNode node, BsvNet net, IEnumerable<(string host, int port)> miners, byte[] rawTx, int timeoutMs = 15000)
    {
        foreach (var link in node.LiveLinks()) link.Send(rawTx);                          // IP-to-IP to players
        return await Broadcaster.BroadcastToManyAsync(net, miners, rawTx, timeoutMs);     // on-chain to miners
    }
}
