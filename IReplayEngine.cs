using System;
using System.Threading.Tasks;

namespace PcapReplayer
{
    /// <summary>
    /// Contract for a PCAP replay engine.
    ///
    /// Dependency Inversion:
    /// <see cref="MainForm"/> and the future CLI host both depend on this abstraction,
    /// not on the concrete <see cref="ReplayEngine"/>. This enables:
    ///
    ///   • Unit-testing callers without sending real UDP packets.
    ///   • A future headless <c>SilentReplayEngine</c> that skips timing delays for
    ///     maximum-speed stress tests.
    ///   • A future <c>MultiAssetReplayEngine</c> that fans out N child engines
    ///     concurrently from a single <c>RunAsync</c> call (the site-simulation scenario).
    ///
    /// Multi-asset CLI usage (future):
    /// <code>
    ///   IReplayEngine[] engines = assets
    ///       .Select(a => (IReplayEngine)new ReplayEngine())
    ///       .ToArray();
    ///
    ///   await Task.WhenAll(
    ///       engines.Zip(configs, (e, c) => e.RunAsync(c)));
    /// </code>
    /// </summary>
    public interface IReplayEngine
    {
        /// <summary>Raised on the thread-pool with a human-readable status message.</summary>
        event Action<string>?    OnLog;

        /// <summary>Raised periodically with the total packets sent so far.</summary>
        event Action<int>?       OnProgress;

        /// <summary>Raised when the replay run completes (or the loop is stopped).</summary>
        event Action?            OnComplete;

        /// <summary>Raised when an unrecoverable error terminates the replay.</summary>
        event Action<Exception>? OnError;

        /// <summary>Signals the engine to stop after the current packet.</summary>
        void Stop();

        /// <summary>
        /// Starts a replay run with the settings and transformer defined in
        /// <paramref name="config"/>. Returns when the replay completes or is stopped.
        /// </summary>
        Task RunAsync(ReplayConfig config);
    }
}
