using System;

namespace PcapReplayer
{
    public static class UsrFrameBuilder
    {
        public static byte[] Build13Bytes(MessageTxState message)
        {
            if (message == null) throw new ArgumentNullException(nameof(message));

            BuildDataBytes(message);

            var frame = new byte[UsrPacketHelper.USR_FRAME_SIZE];
            frame[0] = (byte)(message.Dlc & 0x0F);
            if (message.IsExtended) frame[0] |= 0x80;

            frame[1] = (byte)((message.CanId >> 24) & 0xFF);
            frame[2] = (byte)((message.CanId >> 16) & 0xFF);
            frame[3] = (byte)((message.CanId >> 8) & 0xFF);
            frame[4] = (byte)(message.CanId & 0xFF);
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
    }
}
