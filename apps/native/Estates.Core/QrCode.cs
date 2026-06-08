// Estates.Core/QrCode.cs — a REAL QR Code generator, in-tree, no library. Faithful implementation of the
// QR standard: byte mode, all 40 versions, Reed-Solomon error correction over GF(256), function patterns
// (finder/alignment/timing/format/version), the 8 data masks with penalty-based selection. Produces a
// boolean module matrix (true = dark) that the UI renders to a bitmap (e.g. a receive address / URI).
using System.Collections.Generic;

namespace Estates.Core;

public sealed class QrCode
{
    public const int Low = 0, Medium = 1, Quartile = 2, High = 3;

    public int Size { get; }
    private readonly bool[,] _m;          // [y,x] modules, true = dark
    private readonly bool[,] _fn;         // function-module mask
    public bool Module(int x, int y) => x >= 0 && x < Size && y >= 0 && y < Size && _m[y, x];

    public static QrCode Encode(string text, int ecl = Medium) => EncodeBytes(System.Text.Encoding.UTF8.GetBytes(text), ecl);

    public static QrCode EncodeBytes(byte[] data, int ecl)
    {
        int version;
        for (version = 1; ; version++)
        {
            int cap = NumDataCodewords(version, ecl) * 8;
            int used = 4 + (version <= 9 ? 8 : 16) + data.Length * 8;
            if (used <= cap) break;
            if (version >= 40) throw new System.ArgumentException("data too long for QR");
        }
        var bb = new List<bool>();
        AppendBits(bb, 4, 4);                                   // byte mode
        AppendBits(bb, data.Length, version <= 9 ? 8 : 16);     // char count
        foreach (var b in data) AppendBits(bb, b, 8);
        int dataBits = NumDataCodewords(version, ecl) * 8;
        for (int i = 0; i < 4 && bb.Count < dataBits; i++) bb.Add(false);     // terminator
        while (bb.Count % 8 != 0) bb.Add(false);                              // byte align
        for (int pad = 0xEC; bb.Count < dataBits; pad ^= 0xEC ^ 0x11) AppendBits(bb, pad, 8);
        var dataCw = new byte[bb.Count / 8];
        for (int i = 0; i < bb.Count; i++) if (bb[i]) dataCw[i >> 3] |= (byte)(1 << (7 - (i & 7)));
        byte[] all = AddEcc(dataCw, version, ecl);
        return new QrCode(version, ecl, all);
    }

    private QrCode(int version, int ecl, byte[] allCodewords)
    {
        Size = version * 4 + 17;
        _m = new bool[Size, Size];
        _fn = new bool[Size, Size];
        DrawFunctionPatterns(version);
        DrawCodewords(allCodewords);
        // choose the mask with the lowest penalty
        int best = -1; long bestPen = long.MaxValue;
        for (int mask = 0; mask < 8; mask++)
        {
            ApplyMask(mask); DrawFormatBits(ecl, mask);
            long p = Penalty();
            if (p < bestPen) { bestPen = p; best = mask; }
            ApplyMask(mask);   // XOR again to undo
        }
        ApplyMask(best); DrawFormatBits(ecl, best);
    }

    private static void AppendBits(List<bool> bb, int val, int len) { for (int i = len - 1; i >= 0; i--) bb.Add(((val >> i) & 1) != 0); }

    // ---- function patterns ----
    private void DrawFunctionPatterns(int version)
    {
        for (int i = 0; i < Size; i++) { SetFn(6, i, i % 2 == 0); SetFn(i, 6, i % 2 == 0); }   // timing
        DrawFinder(3, 3); DrawFinder(Size - 4, 3); DrawFinder(3, Size - 4);
        int[] pos = AlignPositions(version);
        for (int i = 0; i < pos.Length; i++)
            for (int j = 0; j < pos.Length; j++)
            {
                if ((i == 0 && j == 0) || (i == 0 && j == pos.Length - 1) || (i == pos.Length - 1 && j == 0)) continue;
                DrawAlign(pos[i], pos[j]);
            }
        DrawFormatBits(0, 0);                         // reserve format areas (filled later)
        DrawVersion(version);
    }

    private void DrawFinder(int cx, int cy)
    {
        for (int dy = -4; dy <= 4; dy++)
            for (int dx = -4; dx <= 4; dx++)
            {
                int x = cx + dx, y = cy + dy; if (x < 0 || x >= Size || y < 0 || y >= Size) continue;
                int d = System.Math.Max(System.Math.Abs(dx), System.Math.Abs(dy));
                SetFn(x, y, d != 2 && d != 4);
            }
    }

    private void DrawAlign(int cx, int cy)
    {
        for (int dy = -2; dy <= 2; dy++)
            for (int dx = -2; dx <= 2; dx++)
                SetFn(cx + dx, cy + dy, System.Math.Max(System.Math.Abs(dx), System.Math.Abs(dy)) != 1);
    }

    private void DrawFormatBits(int ecl, int mask)
    {
        int[] eccFmt = { 1, 0, 3, 2 };               // L,M,Q,H -> spec values
        int data = eccFmt[ecl] << 3 | mask;
        int rem = data;
        for (int i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >> 9) * 0x537);
        int bits = (data << 10 | rem) ^ 0x5412;
        for (int i = 0; i <= 5; i++) SetFn(8, i, GetBit(bits, i));
        SetFn(8, 7, GetBit(bits, 6)); SetFn(8, 8, GetBit(bits, 7)); SetFn(7, 8, GetBit(bits, 8));
        for (int i = 9; i < 15; i++) SetFn(14 - i, 8, GetBit(bits, i));
        for (int i = 0; i < 8; i++) SetFn(Size - 1 - i, 8, GetBit(bits, i));
        for (int i = 8; i < 15; i++) SetFn(8, Size - 15 + i, GetBit(bits, i));
        SetFn(8, Size - 8, true);                    // always-dark module
    }

    private void DrawVersion(int version)
    {
        if (version < 7) return;
        int rem = version;
        for (int i = 0; i < 12; i++) rem = (rem << 1) ^ ((rem >> 11) * 0x1F25);
        int bits = version << 12 | rem;
        for (int i = 0; i < 18; i++) { bool b = GetBit(bits, i); int a = Size - 11 + i % 3, bcol = i / 3; SetFn(a, bcol, b); SetFn(bcol, a, b); }
    }

    private static bool GetBit(int x, int i) => ((x >> i) & 1) != 0;
    private void SetFn(int x, int y, bool dark) { if (x < 0 || x >= Size || y < 0 || y >= Size) return; _m[y, x] = dark; _fn[y, x] = true; }

    // ---- data placement ----
    private void DrawCodewords(byte[] data)
    {
        int i = 0;
        for (int right = Size - 1; right >= 1; right -= 2)
        {
            if (right == 6) right = 5;
            for (int vert = 0; vert < Size; vert++)
                for (int j = 0; j < 2; j++)
                {
                    int x = right - j; bool upward = ((right + 1) & 2) == 0;
                    int y = upward ? Size - 1 - vert : vert;
                    if (_fn[y, x]) continue;
                    bool dark = i < data.Length * 8 && GetBitMsb(data[i >> 3], 7 - (i & 7));
                    _m[y, x] = dark; i++;
                }
        }
    }
    private static bool GetBitMsb(byte b, int i) => ((b >> i) & 1) != 0;

    // ---- masking ----
    private void ApplyMask(int mask)
    {
        for (int y = 0; y < Size; y++)
            for (int x = 0; x < Size; x++)
            {
                if (_fn[y, x]) continue;
                bool inv = mask switch
                {
                    0 => (x + y) % 2 == 0,
                    1 => y % 2 == 0,
                    2 => x % 3 == 0,
                    3 => (x + y) % 3 == 0,
                    4 => (x / 3 + y / 2) % 2 == 0,
                    5 => x * y % 2 + x * y % 3 == 0,
                    6 => (x * y % 2 + x * y % 3) % 2 == 0,
                    _ => ((x + y) % 2 + x * y % 3) % 2 == 0,
                };
                if (inv) _m[y, x] = !_m[y, x];
            }
    }

    private long Penalty()
    {
        long p = 0;
        for (int y = 0; y < Size; y++) p += LineRuns(y, true);
        for (int x = 0; x < Size; x++) p += LineRuns(x, false);
        for (int y = 0; y < Size - 1; y++)
            for (int x = 0; x < Size - 1; x++)
                if (_m[y, x] == _m[y, x + 1] && _m[y, x] == _m[y + 1, x] && _m[y, x] == _m[y + 1, x + 1]) p += 3;
        int dark = 0; foreach (var b in _m) if (b) dark++;
        int total = Size * Size; int k = (System.Math.Abs(dark * 20 - total * 10) + total - 1) / total - 1; if (k > 0) p += k * 10;
        return p;
    }
    private long LineRuns(int idx, bool row)
    {
        long p = 0; int run = 1; bool prev = row ? _m[idx, 0] : _m[0, idx];
        for (int i = 1; i < Size; i++)
        {
            bool c = row ? _m[idx, i] : _m[i, idx];
            if (c == prev) { run++; if (run == 5) p += 3; else if (run > 5) p += 1; }
            else { run = 1; prev = c; }
        }
        return p;
    }

    // ---- error correction ----
    private static byte[] AddEcc(byte[] data, int version, int ecl)
    {
        int numBlocks = NUM_BLOCKS[ecl][version];
        int blockEcc = ECC_PER_BLOCK[ecl][version];
        int rawCw = NumRawDataModules(version) / 8;
        int numShort = numBlocks - rawCw % numBlocks;
        int shortLen = rawCw / numBlocks;            // total codewords per SHORT block (data + ecc)
        var blocks = new byte[numBlocks][];
        byte[] gen = RsDivisor(blockEcc);
        for (int i = 0, k = 0; i < numBlocks; i++)
        {
            int datLen = shortLen - blockEcc + (i < numShort ? 0 : 1);
            var dat = new byte[datLen]; System.Array.Copy(data, k, dat, 0, datLen); k += datLen;
            var block = new byte[shortLen + 1];
            System.Array.Copy(dat, block, datLen);
            byte[] ecc = RsRemainder(dat, gen);
            System.Array.Copy(ecc, 0, block, block.Length - blockEcc, blockEcc);
            blocks[i] = block;
        }
        var result = new byte[rawCw];
        for (int i = 0, k = 0; i < blocks[0].Length; i++)
            for (int j = 0; j < numBlocks; j++)
                if (i != shortLen - blockEcc || j >= numShort) result[k++] = blocks[j][i];
        return result;
    }

    private static byte[] RsDivisor(int degree)
    {
        var r = new byte[degree]; r[degree - 1] = 1;
        int root = 1;
        for (int i = 0; i < degree; i++)
        {
            for (int j = 0; j < degree; j++)
            {
                r[j] = (byte)GfMul(r[j] & 0xFF, root);
                if (j + 1 < degree) r[j] ^= r[j + 1];
            }
            root = GfMul(root, 0x02);
        }
        return r;
    }
    private static byte[] RsRemainder(byte[] data, byte[] gen)
    {
        var r = new byte[gen.Length];
        foreach (var b in data)
        {
            int factor = (b ^ r[0]) & 0xFF;
            System.Array.Copy(r, 1, r, 0, r.Length - 1); r[r.Length - 1] = 0;
            for (int j = 0; j < r.Length; j++) r[j] ^= (byte)GfMul(gen[j] & 0xFF, factor);
        }
        return r;
    }
    private static int GfMul(int x, int y)
    {
        int z = 0;
        for (int i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >> 7) * 0x11D); z ^= ((y >> i) & 1) * x; }
        return z & 0xFF;
    }

    private static int NumRawDataModules(int ver)
    {
        int result = (16 * ver + 128) * ver + 64;
        if (ver >= 2) { int align = ver / 7 + 2; result -= (25 * align - 10) * align - 55; if (ver >= 7) result -= 36; }
        return result;
    }
    private static int NumDataCodewords(int ver, int ecl) => NumRawDataModules(ver) / 8 - ECC_PER_BLOCK[ecl][ver] * NUM_BLOCKS[ecl][ver];

    private static int[] AlignPositions(int ver)
    {
        if (ver == 1) return new int[0];
        int n = ver / 7 + 2;
        int step = ver == 32 ? 26 : (ver * 4 + n * 2 + 1) / (n * 2 - 2) * 2;
        var pos = new int[n]; pos[0] = 6;
        for (int i = n - 1, p = ver * 4 + 10; i >= 1; i--, p -= step) pos[i] = p;
        return pos;
    }

    // standard QR ECC tables, index [ecl(L,M,Q,H)][version 1..40]
    private static readonly int[][] ECC_PER_BLOCK = {
        new[]{-1,7,10,15,20,26,18,20,24,30,18,20,24,26,30,22,24,28,30,28,28,28,28,30,30,26,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30},
        new[]{-1,10,16,26,18,24,16,18,22,22,26,30,22,22,24,24,28,28,26,26,26,26,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28,28},
        new[]{-1,13,22,18,26,18,24,18,22,20,24,28,26,24,20,30,24,28,28,26,30,28,30,30,30,30,28,30,30,30,30,30,30,30,30,30,30,30,30,30,30},
        new[]{-1,17,28,22,16,22,28,26,26,24,28,24,28,22,24,24,30,28,28,26,28,30,24,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30,30},
    };
    private static readonly int[][] NUM_BLOCKS = {
        new[]{-1,1,1,1,1,1,2,2,2,2,4,4,4,4,4,6,6,6,6,7,8,8,9,9,10,12,12,12,13,14,15,16,17,18,19,19,20,21,22,24,25},
        new[]{-1,1,1,1,2,2,4,4,4,5,5,5,8,9,9,10,10,11,13,14,16,17,17,18,20,21,23,25,26,28,29,31,33,35,37,38,40,43,45,47,49},
        new[]{-1,1,1,2,2,4,4,6,6,8,8,8,10,12,16,12,17,16,18,21,20,23,23,25,27,29,34,34,35,38,40,43,45,48,51,53,56,59,62,65,68},
        new[]{-1,1,1,2,4,4,4,5,6,8,8,11,11,16,16,18,16,19,21,25,25,25,34,30,32,35,37,40,42,45,48,51,54,57,60,63,66,70,74,77,81},
    };
}
