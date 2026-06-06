// Estates.Core/Ripemd160.cs — RIPEMD-160 from scratch (no library; .NET dropped it and
// BouncyCastle is third-party = banned). Used for BSV addresses: hash160 = RIPEMD160(SHA256(x)).
namespace Estates.Core;

public static class Ripemd160
{
    private static readonly int[] RL = {
        0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15, 7,4,13,1,10,6,15,3,12,0,9,5,2,14,11,8,
        3,10,14,4,9,15,8,1,2,7,0,6,13,11,5,12, 1,9,11,10,0,8,12,4,13,3,7,15,14,5,6,2,
        4,0,5,9,7,12,2,10,14,1,3,8,11,6,15,13 };
    private static readonly int[] RR = {
        5,14,7,0,9,2,11,4,13,6,15,8,1,10,3,12, 6,11,3,7,0,13,5,10,14,15,8,12,4,9,1,2,
        15,5,1,3,7,14,6,9,11,8,12,2,10,0,4,13, 8,6,4,1,3,11,15,0,5,12,2,13,9,7,10,14,
        12,15,10,4,1,5,8,7,6,2,13,14,0,3,9,11 };
    private static readonly int[] SL = {
        11,14,15,12,5,8,7,9,11,13,14,15,6,7,9,8, 7,6,8,13,11,9,7,15,7,12,15,9,11,7,13,12,
        11,13,6,7,14,9,13,15,14,8,13,6,5,12,7,5, 11,12,14,15,14,15,9,8,9,14,5,6,8,6,5,12,
        9,15,5,11,6,8,13,12,5,12,13,14,11,8,5,6 };
    private static readonly int[] SR = {
        8,9,9,11,13,15,15,5,7,7,8,11,14,14,12,6, 9,13,15,7,12,8,9,11,7,7,12,7,6,15,13,11,
        9,7,15,11,8,6,6,14,12,13,5,14,13,13,7,5, 15,5,8,11,14,14,6,14,6,9,12,9,12,5,15,8,
        8,5,12,9,12,5,14,6,8,13,6,5,15,13,11,11 };
    private static readonly uint[] KL = { 0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu, 0xA953FD4Eu };
    private static readonly uint[] KR = { 0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x7A6D76E9u, 0x00000000u };

    private static uint F(int r, uint x, uint y, uint z) => r switch
    {
        0 => x ^ y ^ z, 1 => (x & y) | (~x & z), 2 => (x | ~y) ^ z, 3 => (x & z) | (y & ~z), _ => x ^ (y | ~z),
    };
    private static uint Rol(uint x, int n) => (x << n) | (x >> (32 - n));
    private static void Put(byte[] b, int o, uint v) { b[o] = (byte)v; b[o + 1] = (byte)(v >> 8); b[o + 2] = (byte)(v >> 16); b[o + 3] = (byte)(v >> 24); }

    public static byte[] Hash(byte[] msg)
    {
        uint h0 = 0x67452301u, h1 = 0xEFCDAB89u, h2 = 0x98BADCFEu, h3 = 0x10325476u, h4 = 0xC3D2E1F0u;
        long ml = (long)msg.Length * 8;
        int rem = msg.Length % 64;
        int padLen = rem < 56 ? 56 - rem : 120 - rem;
        var data = new byte[msg.Length + padLen + 8];
        Array.Copy(msg, data, msg.Length);
        data[msg.Length] = 0x80;
        for (int i = 0; i < 8; i++) data[data.Length - 8 + i] = (byte)(ml >> (8 * i));   // 64-bit LE length

        var X = new uint[16];
        for (int off = 0; off < data.Length; off += 64)
        {
            for (int i = 0; i < 16; i++)
                X[i] = (uint)(data[off + i * 4] | data[off + i * 4 + 1] << 8 | data[off + i * 4 + 2] << 16 | data[off + i * 4 + 3] << 24);
            uint al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
            for (int j = 0; j < 80; j++)
            {
                int round = j / 16;
                uint t = Rol(al + F(round, bl, cl, dl) + X[RL[j]] + KL[round], SL[j]) + el;
                al = el; el = dl; dl = Rol(cl, 10); cl = bl; bl = t;
                t = Rol(ar + F(4 - round, br, cr, dr) + X[RR[j]] + KR[round], SR[j]) + er;
                ar = er; er = dr; dr = Rol(cr, 10); cr = br; br = t;
            }
            uint tmp = h1 + cl + dr;
            h1 = h2 + dl + er; h2 = h3 + el + ar; h3 = h4 + al + br; h4 = h0 + bl + cr; h0 = tmp;
        }
        var outp = new byte[20];
        Put(outp, 0, h0); Put(outp, 4, h1); Put(outp, 8, h2); Put(outp, 12, h3); Put(outp, 16, h4);
        return outp;
    }
}
