using System;
using System.Linq;

namespace PcapReplayer
{
    /// <summary>
    /// Recomputes a <see cref="SignalTxState"/>'s physical and raw value each TX tick
    /// according to its <see cref="SignalGenMode"/>.  Thread-safe for the single TX thread.
    /// </summary>
    public static class SignalValueGenerator
    {
        // One shared instance is fine — CanTransmitter runs on a single background thread.
        private static readonly Random _rng = new();

        /// <summary>
        /// Gets the effective physical range of a signal.
        /// If the signal does not have a valid range in DBC (Min >= Max), it falls back to the theoretical range based on its bit length.
        /// </summary>
        public static void GetEffectiveRange(DbcSignal signal, out double min, out double max)
        {
            if (signal.Min < signal.Max)
            {
                min = signal.Min;
                max = signal.Max;
            }
            else
            {
                int len = Math.Min(63, signal.Length);
                long minRaw = 0;
                long maxRaw = len >= 63 ? long.MaxValue : (1L << len) - 1;
                if (signal.IsSigned)
                {
                    minRaw = len >= 63 ? long.MinValue : -(1L << (len - 1));
                    maxRaw = len >= 63 ? long.MaxValue : (1L << (len - 1)) - 1;
                }
                min = minRaw * signal.Factor + signal.Offset;
                max = maxRaw * signal.Factor + signal.Offset;
                if (min > max)
                {
                    double t = min;
                    min = max;
                    max = t;
                }
            }
        }

        /// <summary>
        /// Updates <paramref name="signal"/> for the current tick.
        /// No-ops when the signal is muted or its mode is <see cref="SignalGenMode.Fixed"/>.
        /// </summary>
        /// <param name="signal">Signal state to update in place.</param>
        /// <param name="elapsedSeconds">Seconds since TX started — used for sine phase.</param>
        public static void Update(SignalTxState signal, double elapsedSeconds)
        {
            if (signal.IsMuted || signal.GenMode == SignalGenMode.Fixed) return;

            GetEffectiveRange(signal.Signal, out double min, out double max);
            if (min >= max) return; // degenerate range

            double physical = ComputePhysical(signal, min, max, elapsedSeconds);

            // Snap to the nearest value-table entry when the signal is a discrete enum.
            if (signal.Signal.ValueTable is { Count: > 0 })
            {
                long targetRaw = (long)Math.Round(
                    (physical - signal.Signal.Offset) / signal.Signal.Factor);
                long closestRaw = signal.Signal.ValueTable.Keys
                    .OrderBy(k => Math.Abs(k - targetRaw))
                    .First();
                physical = closestRaw * signal.Signal.Factor + signal.Signal.Offset;
            }

            if (SignalEncoder.TryEncodePhysical(signal.Signal, physical, out long raw, out _))
            {
                signal.PhysicalValue = physical;
                signal.RawValue      = raw;
            }
        }

        private static double ComputePhysical(
            SignalTxState signal, double min, double max, double elapsedSeconds)
        {
            if (signal.GenMode == SignalGenMode.Random)
                return min + _rng.NextDouble() * (max - min);

            // Sine
            double periodSec = Math.Max(0.1, signal.SinePeriodMs / 1000.0);
            double mid = (min + max) / 2.0;
            double amp = (max - min) / 2.0;
            return mid + amp * Math.Sin(2.0 * Math.PI * elapsedSeconds / periodSec);
        }
    }
}
