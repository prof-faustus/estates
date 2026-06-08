// Estates.Core/BloomFilter.cs — a BIP37 Bloom filter (MurmurHash3 x86_32), in-tree. Craig's SPV uses a
// Bloom filter so a wallet can tell a serving peer "send me transactions matching THESE address/pubkey
// hashes" without revealing the exact set: a probabilistic membership filter (no false negatives; a
// tunable false-positive rate). Insert your watched script-hashes/pubkeys, then test/serve against it.
namespace Estates.Core;

public sealed class BloomFilter
{
    private const int MaxFilterBytes = 36000;     // BIP37 cap
    private const int MaxHashFuncs = 50;
    private readonly byte[] _data;
    private readonly int _hashFuncs;
    private readonly uint _tweak;

    public BloomFilter(int elements, double falsePositiveRate, uint tweak = 0)
    {
        if (elements < 1) elements = 1;
        if (falsePositiveRate <= 0 || falsePositiveRate >= 1) falsePositiveRate = 0.0001;
        int size = (int)(-1.0 / (System.Math.Log(2) * System.Math.Log(2)) * elements * System.Math.Log(falsePositiveRate) / 8.0);
        size = System.Math.Max(1, System.Math.Min(size, MaxFilterBytes));
        _data = new byte[size];
        _hashFuncs = System.Math.Max(1, System.Math.Min((int)(size * 8 / (double)elements * System.Math.Log(2)), MaxHashFuncs));
        _tweak = tweak;
    }

    public int ByteLength => _data.Length;
    public int HashFuncs => _hashFuncs;
    public uint Tweak => _tweak;

    public void Insert(byte[] data)
    {
        for (int i = 0; i < _hashFuncs; i++) { uint bit = BitIndex(i, data); _data[bit >> 3] |= (byte)(1 << (int)(bit & 7)); }
    }

    /// <summary>Probable membership: true means "maybe" (no false negatives), false means "definitely not".</summary>
    public bool Contains(byte[] data)
    {
        for (int i = 0; i < _hashFuncs; i++) { uint bit = BitIndex(i, data); if ((_data[bit >> 3] & (1 << (int)(bit & 7))) == 0) return false; }
        return true;
    }

    private uint BitIndex(int i, byte[] data) => Murmur3((uint)(i * 0xFBA4C795 + _tweak), data) % (uint)(_data.Length * 8);

    /// <summary>The `filterload` wire payload: varint(len)‖data ‖ nHashFuncs(4 LE) ‖ nTweak(4 LE) ‖ nFlags(1).</summary>
    public byte[] FilterLoad(byte flags = 1)
    {
        var o = new List<byte>();
        Varint(o, (ulong)_data.Length); o.AddRange(_data);
        o.AddRange(System.BitConverter.GetBytes((uint)_hashFuncs));
        o.AddRange(System.BitConverter.GetBytes(_tweak));
        o.Add(flags);
        return o.ToArray();
    }

    private static void Varint(List<byte> o, ulong n)
    {
        if (n < 0xfd) o.Add((byte)n);
        else if (n <= 0xffff) { o.Add(0xfd); o.AddRange(System.BitConverter.GetBytes((ushort)n)); }
        else if (n <= 0xffffffff) { o.Add(0xfe); o.AddRange(System.BitConverter.GetBytes((uint)n)); }
        else { o.Add(0xff); o.AddRange(System.BitConverter.GetBytes(n)); }
    }

    // MurmurHash3 x86_32 (BIP37 variant).
    private static uint Rotl(uint x, int r) => (x << r) | (x >> (32 - r));
    private static uint Murmur3(uint seed, byte[] data)
    {
        uint h1 = seed; const uint c1 = 0xcc9e2d51, c2 = 0x1b873593;
        int len = data.Length, i = 0;
        for (; i + 4 <= len; i += 4)
        {
            uint k1 = (uint)(data[i] | (data[i + 1] << 8) | (data[i + 2] << 16) | (data[i + 3] << 24));
            k1 *= c1; k1 = Rotl(k1, 15); k1 *= c2;
            h1 ^= k1; h1 = Rotl(h1, 13); h1 = h1 * 5 + 0xe6546b64;
        }
        uint k = 0; int rem = len - i;
        if (rem == 3) k ^= (uint)data[i + 2] << 16;
        if (rem >= 2) k ^= (uint)data[i + 1] << 8;
        if (rem >= 1) { k ^= data[i]; k *= c1; k = Rotl(k, 15); k *= c2; h1 ^= k; }
        h1 ^= (uint)len;
        h1 ^= h1 >> 16; h1 *= 0x85ebca6b; h1 ^= h1 >> 13; h1 *= 0xc2b2ae35; h1 ^= h1 >> 16;
        return h1;
    }
}
