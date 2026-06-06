// Estates.Core/Broadcast.cs — a FAITHFUL native port of overlay-broadcast
// `crates/broadcast` graph.rs: GB 2623780 B key-graph broadcast encryption.
//
//   * A balanced binary key graph over the member set: the ROOT key is the message
//     key, each LEAF key belongs to one member, and every child-node key
//     authenticated-wraps its parent-node key (Cipher.Wrap, AAD keywrap/v1).
//   * The message is encrypted ONCE under the root key (Cipher.SealForSymmetric, AAD
//     "broadcast/message/v1"). Published encrypted-data-items let each eligible member
//     walk leaf→root to the message key; a non-member / revoked member cannot.
//
// For ESTATES chat the sender builds a FRESH graph per message (fresh keys, no stale
// state) and delivers each member's leaf key by 2-person ECDH (Cipher.EciesEncrypt to
// the member's wallet pubkey) — the two primitives combined exactly as specified.
//
// Heap layout: a power-of-two leaf count L; nodes 0..2L-2; root = 0; parent(i)=(i-1)/2;
// leaves = [L-1 .. 2L-2]; member k → leaf node (L-1 + k).
using System.Text;

namespace Estates.Core;

public sealed class Broadcast
{
    private static readonly byte[] MessageAad = Encoding.ASCII.GetBytes("broadcast/message/v1");

    private readonly int _leaves;                 // power of two ≥ memberCount
    private readonly byte[][] _keys;              // per-node 32-byte key, heap-indexed
    public int MemberCount { get; }

    private Broadcast(int leaves, int memberCount, byte[][] keys)
    {
        _leaves = leaves; MemberCount = memberCount; _keys = keys;
    }

    private static int Parent(int node) => (node - 1) / 2;
    private int LeafOf(int member) => _leaves - 1 + member;
    public int Root => 0;

    /// <summary>Build a graph for `memberCount` members, fresh random key per node.</summary>
    public static Broadcast Build(int memberCount)
    {
        if (memberCount < 1) throw new ArgumentException("need at least one member");
        int leaves = 1;
        while (leaves < memberCount) leaves <<= 1;     // next power of two
        int total = 2 * leaves - 1;
        var keys = new byte[total][];
        for (int i = 0; i < total; i++) keys[i] = System.Security.Cryptography.RandomNumberGenerator.GetBytes(32);
        return new Broadcast(leaves, memberCount, keys);
    }

    /// <summary>A member's leaf key — delivered to that member (here by 2-person ECDH).</summary>
    public byte[] MemberLeafKey(int member)
    {
        if (member < 0 || member >= MemberCount) throw new ArgumentOutOfRangeException(nameof(member));
        return (byte[])_keys[LeafOf(member)].Clone();
    }

    /// <summary>An encrypted data item: a parent-node key wrapped under a child-node key.</summary>
    public sealed record DataItem(int Node, int Parent, Cipher.WrappedKey WrappedParentKey);

    /// <summary>Every non-root node's key wraps its parent's key (GB cl.1).</summary>
    public List<DataItem> EncryptedDataItems()
    {
        var items = new List<DataItem>();
        for (int node = 1; node < _keys.Length; node++)
        {
            int parent = Parent(node);
            items.Add(new DataItem(node, parent, Cipher.Wrap(_keys[node], _keys[parent])));
        }
        return items;
    }

    /// <summary>Encrypt the message ONCE under the root (message) key.</summary>
    public Cipher.SealedMessage EncryptMessage(byte[] plaintext)
        => Cipher.SealForSymmetric(_keys[Root], plaintext, MessageAad);

    /// <summary>Decrypt as `member` using its leaf key + the published items. Null if the
    /// member cannot reach the message key (non-eligible / wrong key / tampered).</summary>
    public static byte[]? MemberDecrypt(int member, int leaves, byte[] leafKey, IReadOnlyList<DataItem> items, Cipher.SealedMessage sealed_)
    {
        int node = leaves - 1 + member;
        byte[] current = (byte[])leafKey.Clone();
        while (node != 0)
        {
            int parent = (node - 1) / 2;
            DataItem? item = null;
            foreach (var it in items) if (it.Node == node && it.Parent == parent) { item = it; break; }
            if (item is null) return null;
            byte[]? up = Cipher.Unwrap(current, item.WrappedParentKey);
            if (up is null) return null;
            current = up;
            node = parent;
        }
        return Cipher.OpenFor(current, null, sealed_, MessageAad);
    }

    /// <summary>The power-of-two leaf count (a decrypting member needs it to locate its leaf).</summary>
    public int Leaves => _leaves;
}
