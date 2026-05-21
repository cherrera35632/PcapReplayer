using System.Collections.Generic;

namespace PcapReplayer
{
    /// <summary>Controls how a signal's value is generated on each TX tick.</summary>
    public enum SignalGenMode
    {
        /// <summary>Value stays at the user-set physical value (default).</summary>
        Fixed,
        /// <summary>A new random value is drawn from [Signal.Min, Signal.Max] on every TX tick.</summary>
        Random,
        /// <summary>Value oscillates as a sine wave between Signal.Min and Signal.Max.</summary>
        Sine
    }
}

namespace PcapReplayer
{
    public sealed class MessageTxState
    {
        public required string Name { get; init; }
        public uint CanId { get; init; }
        public bool IsExtended { get; init; }
        public byte Dlc { get; init; }
        public int PeriodMs { get; set; } = 100;
        public bool Enabled { get; set; } = true;
        public byte[] Data { get; } = new byte[8];
        public List<SignalTxState> Signals { get; } = new();
        public long NextSendTs { get; set; }

        /// <summary>
        /// When non-null and <see cref="IsExtended"/> is true, overrides the Source Address
        /// (low 8 bits of the 29-bit CAN ID) for every transmitted frame of this message.
        /// Set to <c>null</c> to use the SA embedded in the DBC CAN ID.
        /// </summary>
        public byte? OverrideSa { get; set; }
        public string? Comment { get; init; }

        /// <summary>
        /// When <see langword="true"/> the message appears in the Favorites quick-access bar
        /// so the user can navigate to its settings without scrolling the full tree.
        /// </summary>
        public bool IsFavorite { get; set; }

        /// <summary>Non-null when this message contains multiplexed signals.
        /// The multiplexor signal itself lives in <see cref="Signals"/>.
        /// Each group is keyed by the mux index (1, 2, …) and holds its own signal states.</summary>
        public SignalTxState? MultiplexorSignal { get; set; }
        public SortedDictionary<int, MultiplexGroup>? MultiplexGroups { get; set; }

        /// <summary>True when the message has multiplexed signal groups.</summary>
        public bool IsMultiplexed => MultiplexGroups is { Count: > 0 };
    }

    /// <summary>Holds the signal states for one multiplex index value.</summary>
    public sealed class MultiplexGroup
    {
        public int MuxValue { get; init; }
        public List<SignalTxState> Signals { get; } = new();
        public bool Enabled { get; set; } = true;
        /// <summary>Transmission period in milliseconds for this individual mux group.</summary>
        public int PeriodMs { get; set; } = 100;
        /// <summary>Timestamp (via <see cref="System.Diagnostics.Stopwatch"/>) for the next scheduled send.</summary>
        public long NextSendTs { get; set; }
    }

    public sealed class SignalTxState
    {
        public required DbcSignal Signal { get; init; }
        public bool IsMuted { get; set; }
        public double PhysicalValue { get; set; }
        public long RawValue { get; set; }
        public string? Error { get; set; }

        /// <summary>How the value is generated each TX tick. Default is <see cref="SignalGenMode.Fixed"/>.</summary>
        public SignalGenMode GenMode { get; set; } = SignalGenMode.Fixed;

        /// <summary>Sine wave period in milliseconds. Only used when <see cref="GenMode"/> is <see cref="SignalGenMode.Sine"/>.</summary>
        public int SinePeriodMs { get; set; } = 5000;
    }
}
