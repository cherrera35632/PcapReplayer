using System.Collections.Generic;

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
        public string? Comment { get; init; }

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
    }
}
