using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PcapReplayer;

namespace PcapReplayer.Tests
{
    /// <summary>
    /// Unit tests for <see cref="UsrPacketHelper"/>.
    ///
    /// These tests protect the core packet-classification and injection logic
    /// from future regressions without any file I/O or UI involvement.
    ///
    /// Naming convention: Method_Scenario_ExpectedResult
    /// </summary>
    [TestClass]
    public class UsrPacketHelperTests
    {
        // ── Shared test data ──────────────────────────────────────────────────

        // ── PEAK frame builder (mirrors the exact wire format from Classes.cs) ─────
        // Offset 0-1: Frame length (big-endian uint16), typically 36 for 8-byte DLC
        // Offset 2-3: Message type (big-endian uint16)
        //             0x0080 = CAN 2.0 A/B
        //             0x0081 = CAN 2.0 A/B with CRC
        //             0x0090 = CAN FD
        //             0x0091 = CAN FD with CRC
        // Offset 4-27: Flags, timestamps, DLC, CAN ID (see Classes.cs offsets)
        // Offset 28+:  CAN data bytes (DLC bytes)
        private static byte[] MakePeakFrame(byte msgTypeLowByte = 0x80, byte dlc = 8)
        {
            int frameLen = 28 + dlc;   // header(28) + data(dlc)
            var frame    = new byte[frameLen];
            // [0..1] Frame length (big-endian)
            frame[0] = (byte)(frameLen >> 8);
            frame[1] = (byte)(frameLen & 0xFF);
            // [2..3] Message type (big-endian): high byte = 0x00, low byte = type
            frame[2] = 0x00;
            frame[3] = msgTypeLowByte;
            // [4..11] Flags/channel — zero
            // [12..15] Timestamp Hi — zero
            // [16..19] Timestamp Lo — zero
            // [20] Status — zero
            // [21] DLC
            frame[21] = dlc;
            // [22..23] Reserved — zero
            // [24..27] CAN ID — use J1939 example 0x18FEF118
            frame[24] = 0x18; frame[25] = 0xFE; frame[26] = 0xF1; frame[27] = 0x18;
            // [28..] CAN data
            for (int i = 0; i < dlc; i++) frame[28 + i] = (byte)(i + 1);
            return frame;
        }

        // Valid USR info byte for a 13-byte extended CAN frame (DLC=8, EXT=1)
        // 0x88 = 1000 1000 → bit7=1 (EXT), bit6=0 (not RTR), bits3-0=8 (DLC)
        private static byte[] MakeUsrBinaryFrame(int count = 1)
        {
            var frame = new byte[13 * count];
            for (int i = 0; i < count; i++)
            {
                int offset = i * 13;
                frame[offset + 0]  = 0x88;             // Info: EXT, DLC=8 — non-ASCII (>0x7E)
                frame[offset + 1]  = 0x18;             // CAN ID byte 0
                frame[offset + 2]  = 0xFE;             // CAN ID byte 1
                frame[offset + 3]  = 0xF1;             // CAN ID byte 2
                frame[offset + 4]  = 0x00;             // CAN ID byte 3
                // Data bytes 5-12
                for (int d = 5; d < 13; d++) frame[offset + d] = (byte)d;
            }
            return frame;
        }

        private static byte[] AsciiBytes(string s) => Encoding.ASCII.GetBytes(s);

        private static byte[] Concat(byte[] a, byte[] b)
        {
            var r = new byte[a.Length + b.Length];
            Buffer.BlockCopy(a, 0, r, 0, a.Length);
            Buffer.BlockCopy(b, 0, r, a.Length, b.Length);
            return r;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  IsPeakFrame Tests
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void IsPeakFrame_ValidCan20Frame_36Bytes_ReturnsTrue()
            => Assert.IsTrue(UsrPacketHelper.IsPeakFrame(MakePeakFrame(0x80, 8)));

        [TestMethod]
        public void IsPeakFrame_ValidCan20WithCRC_Type0x81_ReturnsTrue()
            => Assert.IsTrue(UsrPacketHelper.IsPeakFrame(MakePeakFrame(0x81, 8)));

        [TestMethod]
        public void IsPeakFrame_ValidCanFD_Type0x90_ReturnsTrue()
            => Assert.IsTrue(UsrPacketHelper.IsPeakFrame(MakePeakFrame(0x90, 8)));

        [TestMethod]
        public void IsPeakFrame_ValidCanFDWithCRC_Type0x91_ReturnsTrue()
            => Assert.IsTrue(UsrPacketHelper.IsPeakFrame(MakePeakFrame(0x91, 8)));

        [TestMethod]
        public void IsPeakFrame_MinDlc_28ByteFrame_ReturnsTrue()
            => Assert.IsTrue(UsrPacketHelper.IsPeakFrame(MakePeakFrame(0x80, 0)));

        [TestMethod]
        public void IsPeakFrame_NullPayload_ReturnsFalse()
            => Assert.IsFalse(UsrPacketHelper.IsPeakFrame(null!));

        [TestMethod]
        public void IsPeakFrame_EmptyPayload_ReturnsFalse()
            => Assert.IsFalse(UsrPacketHelper.IsPeakFrame(Array.Empty<byte>()));

        [TestMethod]
        public void IsPeakFrame_TooShort_19Bytes_ReturnsFalse()
        {
            // Must be ≥ 20 bytes — 19 bytes must fail even with correct type bytes
            var frame = new byte[19];
            frame[0] = 0x00; frame[1] = 0x14;  // length claim = 20 but actual < 20
            frame[2] = 0x00; frame[3] = 0x80;
            Assert.IsFalse(UsrPacketHelper.IsPeakFrame(frame));
        }

        [TestMethod]
        public void IsPeakFrame_WrongTypeBytes_HighByteNonZero_ReturnsFalse()
        {
            // Old (incorrect) fixture: byte[2]=0x80, byte[3]=0x00
            // This gives msgType = (0x80<<8)|0x00 = 0x8000, which is NOT a valid type.
            // Verifies we read the type as a 2-byte big-endian value, not a single byte.
            var frame = MakePeakFrame(0x80, 8);
            frame[2] = 0x80; frame[3] = 0x00;  // wrong byte order
            Assert.IsFalse(UsrPacketHelper.IsPeakFrame(frame),
                "Type 0x8000 is invalid — must read type as 2-byte big-endian [2..3].");
        }

        [TestMethod]
        public void IsPeakFrame_InvalidType_0x82_ReturnsFalse()
        {
            var frame = MakePeakFrame(0x80, 8);
            frame[3] = 0x82;  // unsupported type
            Assert.IsFalse(UsrPacketHelper.IsPeakFrame(frame));
        }

        [TestMethod]
        public void IsPeakFrame_FrameLengthTooLarge_Over96_ReturnsFalse()
        {
            var frame = new byte[100];
            frame[0] = 0x00; frame[1] = 0x64;  // declared length = 100 > 96
            frame[2] = 0x00; frame[3] = 0x80;
            Assert.IsFalse(UsrPacketHelper.IsPeakFrame(frame));
        }

        [TestMethod]
        public void IsPeakFrame_DeclaredLengthExceedsPayload_ReturnsFalse()
        {
            // Claim length of 36 but only provide 20 bytes
            var frame = new byte[20];
            frame[0] = 0x00; frame[1] = 0x24;  // declared = 36, actual = 20
            frame[2] = 0x00; frame[3] = 0x80;
            Assert.IsFalse(UsrPacketHelper.IsPeakFrame(frame));
        }

        [TestMethod]
        public void IsPeakFrame_DeclaredLengthZero_ReturnsFalse()
        {
            var frame = MakePeakFrame(0x80, 8);
            frame[0] = 0x00; frame[1] = 0x00;  // declared length = 0, < 20
            Assert.IsFalse(UsrPacketHelper.IsPeakFrame(frame));
        }

        // ══════════════════════════════════════════════════════════════════════
        //  IsUsrPacket Tests
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void IsUsrPacket_PureMetadata_5Fields_ReturnsTrue_WithMetadata()
        {
            byte[] payload = AsciiBytes("WELL-001|P|R|J0|C1");
            bool result = UsrPacketHelper.IsUsrPacket(payload, out var meta);
            Assert.IsTrue(result);
            Assert.AreEqual("WELL-001|P|R|J0|C1", meta);
        }

        [TestMethod]
        public void IsUsrPacket_PureMetadata_6Fields_ReturnsTrue_WithMetadata()
        {
            byte[] payload = AsciiBytes("WELL-001|P|R|J0|C1|3");
            bool result = UsrPacketHelper.IsUsrPacket(payload, out var meta);
            Assert.IsTrue(result);
            Assert.AreEqual("WELL-001|P|R|J0|C1|3", meta);
        }

        [TestMethod]
        public void IsUsrPacket_PureMetadata_TooFewPipes_3Fields_ReturnsFalse()
        {
            // Only 3 pipes = 4 fields — minimum is 5 fields (4 pipes)
            byte[] payload = AsciiBytes("WELL|P|R|J0");
            bool result = UsrPacketHelper.IsUsrPacket(payload, out var meta);
            Assert.IsFalse(result);
            Assert.IsNull(meta);
        }

        [TestMethod]
        public void IsUsrPacket_PureMetadata_NoPipes_ReturnsFalse()
        {
            byte[] payload = AsciiBytes("WELL001PRJOC1");
            bool result = UsrPacketHelper.IsUsrPacket(payload, out var meta);
            Assert.IsFalse(result);
            Assert.IsNull(meta);
        }

        [TestMethod]
        public void IsUsrPacket_MixedPacket_ReturnsTrue_WithMetadata()
        {
            byte[] header = AsciiBytes("WELL-001|P|R|J0|C1");
            byte[] frames = MakeUsrBinaryFrame(1); // 13 bytes
            byte[] payload = Concat(header, frames);

            bool result = UsrPacketHelper.IsUsrPacket(payload, out var meta);
            Assert.IsTrue(result);
            Assert.AreEqual("WELL-001|P|R|J0|C1", meta);
        }

        [TestMethod]
        public void IsUsrPacket_MixedPacket_MultipleFrames_ReturnsTrue()
        {
            byte[] header  = AsciiBytes("A|B|C|D|E");
            byte[] frames  = MakeUsrBinaryFrame(3); // 39 bytes (3 × 13)
            byte[] payload = Concat(header, frames);

            bool result = UsrPacketHelper.IsUsrPacket(payload, out _);
            Assert.IsTrue(result);
        }

        [TestMethod]
        public void IsUsrPacket_PureBinaryCANFrames_ReturnsFalse()
        {
            // Pure binary — no ASCII header
            byte[] payload = MakeUsrBinaryFrame(2); // 26 bytes
            bool result = UsrPacketHelper.IsUsrPacket(payload, out var meta);
            Assert.IsFalse(result);
            Assert.IsNull(meta);
        }

        [TestMethod]
        public void IsUsrPacket_EmptyPayload_ReturnsFalse()
        {
            bool result = UsrPacketHelper.IsUsrPacket(Array.Empty<byte>(), out var meta);
            Assert.IsFalse(result);
            Assert.IsNull(meta);
        }

        [TestMethod]
        public void IsUsrPacket_NullPayload_ReturnsFalse()
        {
            bool result = UsrPacketHelper.IsUsrPacket(null!, out var meta);
            Assert.IsFalse(result);
            Assert.IsNull(meta);
        }

        [TestMethod]
        public void IsUsrPacket_PeakPayload_ReturnsFalse()
        {
            // A real PEAK CAN 2.0 frame must not be mis-classified as USR
            bool result = UsrPacketHelper.IsUsrPacket(MakePeakFrame(0x80, 8), out var meta);
            Assert.IsFalse(result);
            Assert.IsNull(meta);
        }

        // ══════════════════════════════════════════════════════════════════════
        //  InjectUsrMetadata Tests
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void InjectUsrMetadata_PureMetadataPacket_ReplacesEntirePayload()
        {
            byte[] original = AsciiBytes("WELL-001|P|R|J0|C1|3");
            string @override = "NEW-001|B|CSP|J0|C2|1";

            byte[] result = UsrPacketHelper.InjectUsrMetadata(original, @override);

            Assert.AreEqual(@override, Encoding.ASCII.GetString(result));
        }

        [TestMethod]
        public void InjectUsrMetadata_MixedPacket_ReplacesHeaderPreservesBinaryFrames()
        {
            byte[] header  = AsciiBytes("WELL-001|P|R|J0|C1");
            byte[] frames  = MakeUsrBinaryFrame(1);
            byte[] payload = Concat(header, frames);
            string @override = "NEW-999|P|R|J0|C1|3";

            byte[] result = UsrPacketHelper.InjectUsrMetadata(payload, @override);

            // Override string should appear at start
            byte[] expectedOverride = AsciiBytes(@override);
            for (int i = 0; i < expectedOverride.Length; i++)
                Assert.AreEqual(expectedOverride[i], result[i], $"Mismatch at position {i}");

            // Original binary frames should be at the end — byte-for-byte identical
            Assert.AreEqual(expectedOverride.Length + frames.Length, result.Length);
            for (int i = 0; i < frames.Length; i++)
                Assert.AreEqual(frames[i], result[expectedOverride.Length + i],
                    $"Binary frame corrupted at position {i}");
        }

        [TestMethod]
        public void InjectUsrMetadata_PureBinaryPacket_PrependsOverride()
        {
            byte[] frames  = MakeUsrBinaryFrame(2);
            string @override = "ASSET|P|R|J0|C1";

            byte[] result = UsrPacketHelper.InjectUsrMetadata(frames, @override);

            byte[] expectedPfx = AsciiBytes(@override);
            // Prepended
            for (int i = 0; i < expectedPfx.Length; i++)
                Assert.AreEqual(expectedPfx[i], result[i]);
            // Binary preserved
            for (int i = 0; i < frames.Length; i++)
                Assert.AreEqual(frames[i], result[expectedPfx.Length + i]);
        }

        [TestMethod]
        public void InjectUsrMetadata_EmptyOriginalPayload_ReturnsOverrideOnly()
        {
            byte[] result = UsrPacketHelper.InjectUsrMetadata(Array.Empty<byte>(), "A|B|C|D|E");
            Assert.AreEqual("A|B|C|D|E", Encoding.ASCII.GetString(result));
        }

        [TestMethod]
        public void InjectUsrMetadata_DifferentLengthOverride_WorksCorrectly()
        {
            // Short override into a longer original — no off-by-one errors
            byte[] header  = AsciiBytes("LONGNAME-ASSET-001|P|R|J0|C1");
            byte[] frames  = MakeUsrBinaryFrame(1);
            byte[] payload = Concat(header, frames);
            string @override = "A|B|C|D|E"; // shorter than original header

            byte[] result = UsrPacketHelper.InjectUsrMetadata(payload, @override);

            string expectedStr = Encoding.ASCII.GetString(result, 0, @override.Length);
            Assert.AreEqual(@override, expectedStr);
            Assert.AreEqual(@override.Length + frames.Length, result.Length);
        }

        [TestMethod]
        public void InjectUsrMetadata_MixedPacket_TwoFrames_BinaryFullyPreserved()
        {
            byte[] header  = AsciiBytes("SITE|P|R|J0|C1|2");
            byte[] frames  = MakeUsrBinaryFrame(2);    // 26 bytes
            byte[] payload = Concat(header, frames);
            string @override = "NEWSITE|P|R|J0|C1|3";

            byte[] result = UsrPacketHelper.InjectUsrMetadata(payload, @override);

            byte[] expectedPfx = AsciiBytes(@override);
            Assert.AreEqual(expectedPfx.Length + frames.Length, result.Length,
                "Total length must equal override + binary frames");

            for (int i = 0; i < frames.Length; i++)
                Assert.AreEqual(frames[i], result[expectedPfx.Length + i],
                    $"Binary integrity failure at frame byte {i}");
        }

        // ══════════════════════════════════════════════════════════════════════
        //  FindUsrFrameStart Tests
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void FindUsrFrameStart_PureAsciiPayload_ReturnsNegOne()
        {
            byte[] payload = AsciiBytes("WELL-001|P|R|J0|C1");
            int idx = UsrPacketHelper.FindUsrFrameStart(payload);
            Assert.AreEqual(-1, idx);
        }

        [TestMethod]
        public void FindUsrFrameStart_MixedPayload_ReturnsCorrectBoundary()
        {
            byte[] header  = AsciiBytes("WELL-001|P|R|J0|C1");
            byte[] frames  = MakeUsrBinaryFrame(1);
            byte[] payload = Concat(header, frames);

            int idx = UsrPacketHelper.FindUsrFrameStart(payload);
            Assert.AreEqual(header.Length, idx);
        }

        [TestMethod]
        public void FindUsrFrameStart_PayloadTooShortForFrame_ReturnsNegOne()
        {
            // Payload shorter than one 13-byte frame
            byte[] payload = { 0x88, 0x01, 0x02, 0x03 }; // only 4 bytes, non-ASCII first byte
            int idx = UsrPacketHelper.FindUsrFrameStart(payload);
            Assert.AreEqual(-1, idx, "Must not find a frame start — remaining bytes not a multiple of 13.");
        }

        [TestMethod]
        public void FindUsrFrameStart_NullPayload_ReturnsNegOne()
            => Assert.AreEqual(-1, UsrPacketHelper.FindUsrFrameStart(null!));

        [TestMethod]
        public void FindUsrFrameStart_PureBinaryOneFrame_ReturnZero()
        {
            byte[] payload = MakeUsrBinaryFrame(1); // 13 bytes, starts with 0x88
            int idx = UsrPacketHelper.FindUsrFrameStart(payload);
            Assert.AreEqual(0, idx);
        }

        // ══════════════════════════════════════════════════════════════════════
        //  IsAllAscii Tests
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void IsAllAscii_PrintableAsciiString_ReturnsTrue()
        {
            byte[] data = AsciiBytes("Hello|World");
            Assert.IsTrue(UsrPacketHelper.IsAllAscii(data, 0, data.Length));
        }

        [TestMethod]
        public void IsAllAscii_ContainsBinaryByte_ReturnsFalse()
        {
            byte[] data = Concat(AsciiBytes("WELL"), new byte[] { 0x88 });
            Assert.IsFalse(UsrPacketHelper.IsAllAscii(data, 0, data.Length));
        }

        [TestMethod]
        public void IsAllAscii_PartialRange_ChecksOnlySlice()
        {
            // All-ASCII in first 4 bytes, binary after
            byte[] data = Concat(AsciiBytes("WELL"), new byte[] { 0x88, 0x90 });
            Assert.IsTrue(UsrPacketHelper.IsAllAscii(data, 0, 4),  "First 4 bytes ARE all ASCII");
            Assert.IsFalse(UsrPacketHelper.IsAllAscii(data, 0, 6), "Full range contains binary");
        }

        [TestMethod]
        public void IsAllAscii_NullData_ReturnsFalse()
            => Assert.IsFalse(UsrPacketHelper.IsAllAscii(null!, 0, 0));
    }
}
