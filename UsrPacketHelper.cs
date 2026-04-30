using System.Text;

namespace PcapReplayer
{
    /// <summary>
    /// Shared, stateless helpers for USR-CANET200 and PEAK CAN Gateway packet
    /// classification and USR metadata injection.
    ///
    /// Extracted from PcapAnalyzer and ReplayEngine so that every public method
    /// can be directly unit-tested without touching the UI or file system.
    /// </summary>
    public static class UsrPacketHelper
    {
        /// <summary>USR-CANET200 CAN frame size: 1 info + 4 ID + 8 data bytes.</summary>
        public const int USR_FRAME_SIZE = 13;

        // ── Protocol detection ────────────────────────────────────────────────

        /// <summary>
        /// Determines whether <paramref name="payload"/> is a PEAK CAN Gateway frame.
        ///
        /// Mirrors <c>PeakCanParser.CanParse</c> in the gateway exactly:
        /// <list type="bullet">
        ///   <item>Payload must be ≥ 20 bytes (minimum PEAK frame header size).</item>
        ///   <item>Bytes [2..3] as big-endian uint16 = message type. Known types:
        ///     0x80 (CAN 2.0 A/B), 0x81 (CAN 2.0 A/B + CRC),
        ///     0x90 (CAN FD), 0x91 (CAN FD + CRC).</item>
        ///   <item>Bytes [0..1] as big-endian uint16 = declared frame length.
        ///     Must be 20–96 and ≤ actual payload length.</item>
        /// </list>
        /// </summary>
        public static bool IsPeakFrame(byte[] payload)
        {
            // Minimum PEAK header is 20 bytes
            if (payload == null || payload.Length < 20) return false;

            // Message type at offset [2..3] (Network Byte Order / big-endian)
            int msgType = (payload[2] << 8) | payload[3];
            if (msgType != 0x80 && msgType != 0x81 &&
                msgType != 0x90 && msgType != 0x91)
                return false;

            // Frame length at offset [0..1] (Network Byte Order)
            int length = (payload[0] << 8) | payload[1];
            return length >= 20 && length <= 96 && length <= payload.Length;
        }

        /// <summary>
        /// Determines whether <paramref name="payload"/> is a USR-CANET200 packet
        /// (either a pure ASCII metadata burst or a mixed ASCII-header + binary CAN frame packet).
        /// </summary>
        /// <param name="payload">UDP payload bytes.</param>
        /// <param name="metadataString">
        /// When the method returns <c>true</c>, contains the extracted pipe-delimited metadata
        /// string (e.g. <c>"WELL-001|P|R|J0|C1|3"</c>), or <c>null</c> if the packet is a pure
        /// binary CAN frame packet with no ASCII header.
        /// </param>
        public static bool IsUsrPacket(byte[] payload, out string? metadataString)
        {
            metadataString = null;
            if (payload == null || payload.Length == 0) return false;

            // Case 1: Pure ASCII metadata burst (the device's "register packet")
            if (IsAllAscii(payload, 0, payload.Length))
            {
                string s = Encoding.ASCII.GetString(payload).Trim('\0', '\r', '\n');
                if (s.Contains('|'))
                {
                    var parts = s.Split('|');
                    if (parts.Length >= 5)
                    {
                        metadataString = s;
                        return true;
                    }
                }
                return false;
            }

            // Case 2: Mixed packet — ASCII header + binary 13-byte CAN frames
            int frameStart = FindUsrFrameStart(payload);
            if (frameStart <= 0) return false; // frameStart must be > 0 (there must be an ASCII header)

            string header = Encoding.ASCII.GetString(payload, 0, frameStart).Trim('\0', '\r', '\n');
            if (header.Contains('|'))
            {
                var parts = header.Split('|');
                if (parts.Length >= 5)
                    metadataString = header;
                return true;
            }

            return false;
        }

        /// <summary>
        /// Replaces the ASCII metadata header in a USR payload with <paramref name="overrideString"/>.
        /// Binary CAN frame bytes (everything after the first non-ASCII boundary) are preserved
        /// byte-for-byte. If the payload has no ASCII header, the override string is prepended.
        /// </summary>
        public static byte[] InjectUsrMetadata(byte[] payload, string overrideString)
        {
            if (payload == null || payload.Length == 0)
                return Encoding.ASCII.GetBytes(overrideString ?? string.Empty);

            byte[] overrideBytes = Encoding.ASCII.GetBytes(overrideString ?? string.Empty);

            // Case 1: Pure ASCII metadata packet (no binary CAN frames) — replace entirely
            if (IsAllAscii(payload, 0, payload.Length))
                return overrideBytes;

            // Case 2: Mixed packet — locate binary CAN frame section boundary
            int frameStart = FindUsrFrameStart(payload);

            if (frameStart <= 0)
            {
                // No ASCII header found — prepend the override in front of existing binary frames
                byte[] result = new byte[overrideBytes.Length + payload.Length];
                Buffer.BlockCopy(overrideBytes, 0, result, 0, overrideBytes.Length);
                Buffer.BlockCopy(payload, 0, result, overrideBytes.Length, payload.Length);
                return result;
            }

            // Has ASCII header [0..frameStart-1] + binary frames [frameStart..end]
            int binaryLen = payload.Length - frameStart;
            byte[] injected = new byte[overrideBytes.Length + binaryLen];
            Buffer.BlockCopy(overrideBytes, 0, injected, 0, overrideBytes.Length);
            Buffer.BlockCopy(payload, frameStart, injected, overrideBytes.Length, binaryLen);
            return injected;
        }

        // ── Internal helpers (public for testability) ─────────────────────────

        /// <summary>
        /// Returns the byte index where the binary CAN frame section begins within a
        /// mixed USR payload, or -1 if no valid binary boundary is found.
        ///
        /// Logic: scan for the first non-ASCII byte whose remaining byte count is a
        /// non-zero multiple of <see cref="USR_FRAME_SIZE"/>.
        /// </summary>
        public static int FindUsrFrameStart(byte[] data)
        {
            if (data == null) return -1;

            for (int i = 0; i <= data.Length - USR_FRAME_SIZE; i++)
            {
                byte b = data[i];

                // Header region: skip printable ASCII and common whitespace (CR/LF/Tab)
                if ((b >= 0x20 && b <= 0x7E) || b == 0x0D || b == 0x0A || b == 0x09)
                    continue;

                // First non-ASCII byte — this must be a USR CAN info byte.
                // Info byte structure (USR-CANET200 Manual §2.2.4):
                //   Bit 7:   FF  (1=Extended, 0=Standard)
                //   Bit 6:   RTR (1=Remote frame)
                //   Bits 5-4: Reserved — MUST be 0
                //   Bits 3-0: DLC (0–8 for classic CAN)
                // Mirrors UsrCanetParser.IsValidInfoByte in the gateway.
                bool reservedClear = (b & 0x30) == 0;   // bits 5-4 must be 0
                bool dlcValid      = (b & 0x0F) <= 8;   // DLC 0-8

                if (!reservedClear || !dlcValid)
                    return -1;   // Non-ASCII byte is not a valid info byte → not a USR mixed packet

                // Validate that the remaining bytes form complete 13-byte frames
                int remaining = data.Length - i;
                if (remaining >= USR_FRAME_SIZE && remaining % USR_FRAME_SIZE == 0)
                    return i;

                return -1;  // Remaining bytes don't fit frame structure
            }
            return -1;
        }

        /// <summary>
        /// Returns <c>true</c> if every byte in <paramref name="data"/> between
        /// <paramref name="start"/> and <paramref name="start"/>+<paramref name="length"/>-1
        /// is a printable ASCII character or common whitespace (tab, LF, CR).
        /// </summary>
        public static bool IsAllAscii(byte[] data, int start, int length)
        {
            if (data == null) return false;
            for (int i = start; i < start + length; i++)
            {
                byte b = data[i];
                if (b > 0x7E || (b < 0x20 && b != 0x09 && b != 0x0A && b != 0x0D))
                    return false;
            }
            return true;
        }
    }
}
