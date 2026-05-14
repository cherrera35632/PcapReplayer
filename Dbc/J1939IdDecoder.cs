namespace PcapReplayer
{
    public readonly record struct J1939IdInfo(byte Priority, uint Pgn, byte SourceAddress, byte PduFormat, byte PduSpecific);

    public static class J1939IdDecoder
    {
        public static bool TryDecode(uint canId, bool isExtended, out J1939IdInfo info)
        {
            info = default;
            if (!isExtended || canId > 0x1FFFFFFFu)
                return false;

            byte priority     = (byte)((canId >> 26) & 0x07);
            byte dataPage     = (byte)((canId >> 24) & 0x01);
            byte pduFormat    = (byte)((canId >> 16) & 0xFF);
            byte pduSpecific  = (byte)((canId >> 8) & 0xFF);
            byte source       = (byte)(canId & 0xFF);
            uint pgn          = pduFormat < 240
                ? (uint)((dataPage << 16) | (pduFormat << 8))
                : (uint)((dataPage << 16) | (pduFormat << 8) | pduSpecific);

            info = new J1939IdInfo(priority, pgn, source, pduFormat, pduSpecific);
            return true;
        }
    }
}
