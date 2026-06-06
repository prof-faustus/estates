// Estates.Core/WalletStore.cs — a persistent, password-encrypted wallet FILE. This is the
// point of a wallet: the seed lives on disk (encrypted at rest), so you can CLOSE the app
// and NOT lose your money — reopen, unlock, and your keys/funds are still there. (The P2P
// game/session is ephemeral; the wallet is NOT.)
//
// File layout: "ESTW"(4) | salt(16) | nonce(12) | AES-256-GCM(seed, key=PBKDF2-SHA256(pwd,salt),
// aad=salt). Wrong password / tampered file → Open returns null (never throws).
using System.Security.Cryptography;

namespace Estates.Core;

public static class WalletStore
{
    private const int Pbkdf2Iterations = 200_000;
    private static readonly byte[] Magic = "ESTW"u8.ToArray();

    /// <summary>The default wallet-file path (%APPDATA%\ESTATES\wallet.dat).</summary>
    public static string DefaultPath()
    {
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "ESTATES");
        Directory.CreateDirectory(dir);
        return Path.Combine(dir, "wallet.dat");
    }

    public static bool Exists(string path) => File.Exists(path);

    /// <summary>Write the seed to an encrypted wallet file under `password` (overwrites).</summary>
    public static void Create(string path, byte[] seed, string password)
    {
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ct = Cipher.Seal(key, nonce, seed, salt);   // AAD = salt
        Array.Clear(key);
        using var fs = File.Create(path);
        fs.Write(Magic); fs.Write(salt); fs.Write(nonce); fs.Write(ct);
    }

    /// <summary>Load + decrypt the seed with `password`. null on wrong password / tampered / missing.</summary>
    public static byte[]? Open(string path, string password)
    {
        try
        {
            byte[] d = File.ReadAllBytes(path);
            if (d.Length < 4 + 16 + 12 + 16) return null;
            if (!d.AsSpan(0, 4).SequenceEqual(Magic)) return null;
            byte[] salt = d[4..20]; byte[] nonce = d[20..32]; byte[] ct = d[32..];
            byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
            byte[]? seed = Cipher.Open(key, nonce, ct, salt);
            Array.Clear(key);
            return seed;
        }
        catch { return null; }
    }

    /// <summary>Load the seed if it exists, else create a fresh random one and persist it.</summary>
    public static byte[] OpenOrCreate(string path, string password)
    {
        if (Exists(path))
        {
            byte[]? s = Open(path, password);
            if (s is not null) return s;
            throw new InvalidOperationException("wrong wallet password");
        }
        byte[] seed = RandomNumberGenerator.GetBytes(32);
        Create(path, seed, password);
        return seed;
    }
}
