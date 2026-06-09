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

    /// <summary>Write the seed to an encrypted wallet file under `password`. ABSOLUTE SAFETY RULE: a wallet
    /// file is NEVER silently overwritten or deleted — if one already exists it is BACKED UP first (an
    /// append-only set of timestamped copies is kept FOREVER, never pruned), so a previous seed can never
    /// be lost. Losing keys = losing a life; this makes overwrite-loss impossible by construction.</summary>
    /// <summary>Extra, independent backup roots that EVERY wallet write fans out to (the app adds
    /// D:\claude\backups). Each backup is a NEW, uniquely-named, READ-ONLY file that is NEVER deleted or
    /// overwritten — the user would rather 1 TB of tiny files than ever lose one seed.</summary>
    public static readonly List<string> ExtraBackupDirs = new();

    public static void Create(string path, byte[] seed, string password)
    {
        BackupFile(path, "pre");    // ON ANY WRITE: back up the PRIOR file first (read-only, never deleted)
        byte[] salt = RandomNumberGenerator.GetBytes(16);
        byte[] key = Rfc2898DeriveBytes.Pbkdf2(password, salt, Pbkdf2Iterations, HashAlgorithmName.SHA256, 32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] ct = Cipher.Seal(key, nonce, seed, salt);   // AAD = salt
        Array.Clear(key);
        // temp file then atomic move — the prior file is NEVER truncated in place.
        string tmp = path + ".new-" + Guid.NewGuid().ToString("N");
        using (var fs = File.Create(tmp)) { fs.Write(Magic); fs.Write(salt); fs.Write(nonce); fs.Write(ct); }
        if (File.Exists(path)) File.Replace(tmp, path, path + ".prev");   // keeps the immediately-prior copy too
        else File.Move(tmp, path);
        BackupFile(path, "post");   // ON ANY WRITE: back up the NEW file too (read-only, never deleted)
    }

    /// <summary>Copy `path` (if it exists) to EVERY backup root — a unique, timestamped, READ-ONLY file that
    /// is never overwritten or deleted. Roots = a wallet-backups folder beside the file + every ExtraBackupDir
    /// (e.g. claude\backups). A failure to back up never blocks the wallet write, but we try every root.</summary>
    private static void BackupFile(string path, string tag)
    {
        try
        {
            if (!File.Exists(path)) return;
            byte[] data = File.ReadAllBytes(path);
            var roots = new List<string> { Path.Combine(Path.GetDirectoryName(path) ?? ".", "wallet-backups") };
            roots.AddRange(ExtraBackupDirs);
            foreach (var d in roots)
            {
                try
                {
                    if (string.IsNullOrWhiteSpace(d)) continue;
                    Directory.CreateDirectory(d);
                    // sequential, never-reused names: estates-wallet-backup-001.dat, -002.dat, …
                    int next = NextBackupNumber(d);
                    string bp;
                    // estates-wallet-backup-<seq>-<UTC date-time>.dat  (sequential number + exact date)
                    do { bp = Path.Combine(d, $"estates-wallet-backup-{next:000}-{DateTime.UtcNow:yyyyMMdd-HHmmss-fffffff}Z.dat"); next++; } while (File.Exists(bp));
                    File.WriteAllBytes(bp, data);
                    File.SetAttributes(bp, FileAttributes.ReadOnly);   // a backup is immutable + read-only
                }
                catch { }
            }
        }
        catch { }
    }

    private static int NextBackupNumber(string dir)
    {
        int max = 0; const string pfx = "estates-wallet-backup-";
        try
        {
            foreach (var f in Directory.GetFiles(dir, "estates-wallet-backup-*.dat"))
            {
                string n = Path.GetFileNameWithoutExtension(f);
                if (!n.StartsWith(pfx)) continue;
                string rest = n[pfx.Length..];                       // "<seq>-<date>…"
                int j = 0; while (j < rest.Length && char.IsDigit(rest[j])) j++;   // leading seq digits
                if (j > 0 && int.TryParse(rest[..j], out int v) && v > max) max = v;
            }
        }
        catch { }
        return max + 1;
    }

    /// <summary>Every wallet copy we still have (the live file + every backup), newest first — for recovery.</summary>
    public static IReadOnlyList<string> AllCopies(string path)
    {
        var list = new List<string>();
        try { if (File.Exists(path)) list.Add(path); } catch { }
        try
        {
            string bdir = Path.Combine(Path.GetDirectoryName(path) ?? ".", "wallet-backups");
            if (Directory.Exists(bdir)) list.AddRange(Directory.GetFiles(bdir).OrderByDescending(File.GetLastWriteTimeUtc));
        }
        catch { }
        return list;
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
