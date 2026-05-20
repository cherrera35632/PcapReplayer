using System;
using System.Collections.Generic;
using System.Linq;

namespace PcapReplayer
{
    public static class UsrFrameBuilder
    {
        /// <summary>
        /// Returns the effective 29-bit CAN ID to transmit, substituting the low 8 bits
        /// (Source Address) when <see cref="MessageTxState.OverrideSa"/> is set.
        /// For standard (11-bit) messages the ID is returned unchanged.
        /// </summary>
        private static uint EffectiveCanId(MessageTxState message)
        {
            if (message.IsExtended && message.OverrideSa.HasValue)
                return (message.CanId & 0xFFFFFF00u) | message.OverrideSa.Value;
            return message.CanId;
        }

        public static byte[] Build13Bytes(MessageTxState message)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));

            BuildDataBytes(message);

            var frame = new byte[UsrPacketHelper.USR_FRAME_SIZE];
            frame[0] = (byte)(message.Dlc & 0x0F);
            if (message.IsExtended) frame[0] |= 0x80;

            uint txId = EffectiveCanId(message);
            frame[1] = (byte)((txId >> 24) & 0xFF);
            frame[2] = (byte)((txId >> 16) & 0xFF);
            frame[3] = (byte)((txId >> 8) & 0xFF);
            frame[4] = (byte)(txId & 0xFF);
            Array.Copy(message.Data, 0, frame, 5, Math.Min(8, message.Data.Length));
            return frame;
        }

        /// <summary>
        /// Builds a 13-byte USR frame for a specific multiplex group.
        /// The multiplexor signal is set to <paramref name="muxValue"/> and
        /// only signals in the corresponding group are packed.
        /// </summary>
        public static byte[] Build13BytesForMuxGroup(MessageTxState message, int muxValue)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));

            BuildDataBytesForMuxGroup(message, muxValue);

            var frame = new byte[UsrPacketHelper.USR_FRAME_SIZE];
            frame[0] = (byte)(message.Dlc & 0x0F);
            if (message.IsExtended) frame[0] |= 0x80;

            uint txId = EffectiveCanId(message);
            frame[1] = (byte)((txId >> 24) & 0xFF);
            frame[2] = (byte)((txId >> 16) & 0xFF);
            frame[3] = (byte)((txId >> 8) & 0xFF);
            frame[4] = (byte)(txId & 0xFF);
            Array.Copy(message.Data, 0, frame, 5, Math.Min(8, message.Data.Length));
            return frame;
        }

        public static byte[] BuildDataBytes(MessageTxState message)
        {
            Array.Clear(message.Data, 0, message.Data.Length);
            foreach (var signal in message.Signals)
            {
                if (signal.IsMuted) continue;
                SignalEncoder.PackBits(message.Data, signal.Signal, signal.RawValue);
            }

            return message.Data;
        }

        /// <summary>
        /// Packs the data bytes for one specific multiplex group:
        /// non-muxed signals + multiplexor value + the group's signals.
        /// </summary>
        public static byte[] BuildDataBytesForMuxGroup(MessageTxState message, int muxValue)
        {
            Array.Clear(message.Data, 0, message.Data.Length);

            // Pack non-multiplexed normal signals
            foreach (var signal in message.Signals)
            {
                if (signal.IsMuted) continue;
                if (signal.Signal.MultiplexIndicator != null) continue; // skip mux & muxed signals
                SignalEncoder.PackBits(message.Data, signal.Signal, signal.RawValue);
            }

            // Pack the multiplexor signal with the mux value
            if (message.MultiplexorSignal != null)
            {
                SignalEncoder.PackBits(message.Data, message.MultiplexorSignal.Signal, muxValue);
            }

            // Pack the group signals
            if (message.MultiplexGroups != null &&
                message.MultiplexGroups.TryGetValue(muxValue, out var group))
            {
                foreach (var signal in group.Signals)
                {
                    if (signal.IsMuted) continue;
                    SignalEncoder.PackBits(message.Data, signal.Signal, signal.RawValue);
                }
            }

            return message.Data;
        }
    }
}
