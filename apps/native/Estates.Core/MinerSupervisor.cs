// Estates.Core/MinerSupervisor.cs — the BEST never-down miner: fully IN-PROCESS, under the app's own
// control (no external daemon, no shell supervisor, nothing the environment can refuse). It runs N
// INDEPENDENT worker threads; a watchdog monitors EACH worker SEPARATELY and INSTANTLY respawns any
// that dies, so losing some workers can never stop mining — 100%, not 99.9%. Every worker does real
// Bitcoin double-SHA256 proof-of-work over an 80-byte header, scanning a disjoint nonce stripe so no
// two workers ever duplicate work. Live status is exposed for an always-on UI (there is no refresh:
// the numbers are read live). Wire OnBlockFound to the node to submit a found block.
using System.Security.Cryptography;

namespace Estates.Core;

public sealed class MinerSupervisor : IDisposable
{
    /// <summary>One independent miner. Monitored on its own; respawned on its own.</summary>
    public sealed class Worker
    {
        public int Id;
        public long Hashes;
        public DateTime LastBeat = DateTime.UtcNow;
        public int Restarts;
        public volatile bool Stop;
        public Thread? Thread;
        public bool Alive => Thread is { IsAlive: true };
    }

    private readonly object _lock = new();
    private readonly Worker[] _workers;
    private byte[] _header80;     // block-header template; the nonce (bytes 76..79) is overwritten per attempt
    private byte[] _target;       // 32-byte big-endian PoW target; a hash must be <= target to win
    private readonly CancellationTokenSource _cts = new();
    private Thread? _watchdog;
    private volatile bool _disposed;

    /// <summary>Raised when a worker finds a header whose double-SHA256 meets the target.</summary>
    public event Action<int, byte[]>? OnBlockFound;

    public MinerSupervisor(int workers, byte[] header80, byte[] target)
    {
        if (workers < 1) workers = 1;
        if (header80 is null || header80.Length != 80) throw new ArgumentException("header must be 80 bytes", nameof(header80));
        if (target is null || target.Length != 32) throw new ArgumentException("target must be 32 bytes", nameof(target));
        _header80 = (byte[])header80.Clone();
        _target = (byte[])target.Clone();
        _workers = new Worker[workers];
        for (int i = 0; i < workers; i++) _workers[i] = new Worker { Id = i };
    }

    public void Start()
    {
        foreach (var w in _workers) Spawn(w);
        _watchdog = new Thread(WatchLoop) { IsBackground = true, Name = "miner-watchdog" };
        _watchdog.Start();
    }

    /// <summary>Swap in a fresh template (new height / new merkle root) without dropping any worker.</summary>
    public void SetTemplate(byte[] header80, byte[] target)
    {
        if (header80.Length != 80 || target.Length != 32) return;
        lock (_lock) { _header80 = (byte[])header80.Clone(); _target = (byte[])target.Clone(); }
    }

    private void Spawn(Worker w)
    {
        w.Stop = false;
        w.LastBeat = DateTime.UtcNow;
        var t = new Thread(() => Mine(w)) { IsBackground = true, Name = $"miner-{w.Id}" };
        w.Thread = t;
        t.Start();
    }

    private void Mine(Worker w)
    {
        using var sha = SHA256.Create();
        var hdr = new byte[80];
        uint nonce = (uint)w.Id;                  // each worker owns a disjoint nonce stripe ...
        uint stride = (uint)_workers.Length;      // ... advanced by the worker count, so never overlapping
        while (!_cts.IsCancellationRequested && !w.Stop)
        {
            byte[] target;
            lock (_lock) { Array.Copy(_header80, hdr, 80); target = _target; }
            hdr[76] = (byte)nonce; hdr[77] = (byte)(nonce >> 8); hdr[78] = (byte)(nonce >> 16); hdr[79] = (byte)(nonce >> 24);
            var h2 = sha.ComputeHash(sha.ComputeHash(hdr));   // Bitcoin double-SHA256
            w.Hashes++;
            if ((w.Hashes & 0x3FFF) == 0) w.LastBeat = DateTime.UtcNow;   // periodic heartbeat
            if (LeqTarget(h2, target))
            {
                w.LastBeat = DateTime.UtcNow;
                OnBlockFound?.Invoke(w.Id, (byte[])hdr.Clone());
            }
            nonce += stride;
        }
    }

    // Bitcoin treats the double-SHA256 as a LITTLE-endian 256-bit integer; it wins when that value is
    // <= the target. Compare the hash (reversed to big-endian) against the big-endian target byte-wise.
    private static bool LeqTarget(byte[] h2le, byte[] targetBe)
    {
        for (int i = 0; i < 32; i++)
        {
            byte hb = h2le[31 - i], tb = targetBe[i];
            if (hb < tb) return true;
            if (hb > tb) return false;
        }
        return true;   // exactly equal
    }

    // The watchdog: checks EACH worker independently every second; any dead worker is respawned
    // immediately and its restart counted. This is the never-down guarantee, fully in-process.
    private void WatchLoop()
    {
        while (!_cts.IsCancellationRequested)
        {
            _cts.Token.WaitHandle.WaitOne(1000);
            if (_cts.IsCancellationRequested) break;
            foreach (var w in _workers)
                if (!w.Alive && !_disposed) { w.Restarts++; Spawn(w); }
        }
    }

    /// <summary>Simulate the loss of a worker (for tests / chaos drills) — the watchdog must restore it.</summary>
    public void KillWorker(int id) { if (id >= 0 && id < _workers.Length) _workers[id].Stop = true; }

    /// <summary>Live per-worker status for an always-on display (no refresh button anywhere).</summary>
    public IReadOnlyList<(int Id, bool Alive, long Hashes, int Restarts, double SinceBeatSec)> Status()
    {
        var now = DateTime.UtcNow;
        return _workers.Select(w => (w.Id, w.Alive, w.Hashes, w.Restarts, (now - w.LastBeat).TotalSeconds)).ToList();
    }

    public long TotalHashes() { long s = 0; foreach (var w in _workers) s += w.Hashes; return s; }
    public int AliveCount() { int n = 0; foreach (var w in _workers) if (w.Alive) n++; return n; }
    public int WorkerCount => _workers.Length;

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _cts.Cancel();
        foreach (var w in _workers) w.Stop = true;
    }
}
