using System;
using System.Linq;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class UsrFrameBuilderTests
    {
        [TestMethod]
        public void Build13Bytes_OutputLength_IsAlwaysThirteen()
        {
            byte[] frame = UsrFrameBuilder.Build13Bytes(CreateMessage(0x123, false, 8));

            Assert.AreEqual(13, frame.Length);
        }

        [TestMethod]
        public void Build13Bytes_ExtendedMessage_SetsInfoByteBit7()
        {
            byte[] frame = UsrFrameBuilder.Build13Bytes(CreateMessage(0x18FECAFE, true, 8));

            Assert.AreEqual(0x88, frame[0]);
        }

        [TestMethod]
        public void Build13Bytes_DlcLessThanEight_ZeroPadsTrailingBytes()
        {
            var signal = new SignalTxState
            {
                Signal = CreateSignal(0, 8, true, false),
                RawValue = 0x12,
                PhysicalValue = 0x12,
                Error = null
            };
            byte[] frame = UsrFrameBuilder.Build13Bytes(CreateMessage(0x123, false, 3, signal));

            Assert.AreEqual(0x03, frame[0]);
            Assert.AreEqual(0x12, frame[5]);
            CollectionAssert.AreEqual(new byte[7], frame.Skip(6).Take(7).ToArray());
        }

        [TestMethod]
        public void Build13Bytes_WithAsciiHeader_RoundTripsThroughUsrDetection()
        {
            string header = "ASSET|Equip|Mfg|Db|CAN1";
            byte[] headerBytes = Encoding.ASCII.GetBytes(header);
            byte[] frame = UsrFrameBuilder.Build13Bytes(CreateMessage(0x18FECAFE, true, 8));
            byte[] payload = headerBytes.Concat(frame).ToArray();

            bool isUsr = UsrPacketHelper.IsUsrPacket(payload, out _);
            int frameStart = UsrPacketHelper.FindUsrFrameStart(payload);

            Assert.IsTrue(isUsr);
            Assert.AreEqual(headerBytes.Length, frameStart);
        }

        private static MessageTxState CreateMessage(uint canId, bool isExtended, byte dlc, params SignalTxState[] signals)
        {
            var message = new MessageTxState
            {
                Name       = "Msg",
                CanId      = canId,
                IsExtended = isExtended,
                Dlc        = dlc,
                Enabled    = true,
                PeriodMs   = 10
            };
            foreach (var signal in signals) message.Signals.Add(signal);
            return message;
        }

        private static DbcSignal CreateSignal(int startBit, int length, bool littleEndian, bool signed)
            => new()
            {
                Name           = "Sig",
                StartBit       = startBit,
                Length         = length,
                IsLittleEndian = littleEndian,
                IsSigned       = signed,
                Factor         = 1,
                Offset         = 0,
                Min            = 0,
                Max            = 255,
                Unit           = string.Empty
            };

        [TestMethod]
        public void Build13Bytes_WithOverrideSa_ReplacesLowByteOfCanId()
        {
            // Arrange: DBC ID = 0x18FECA_FE (SA = 0xFE), override with 0x11
            var message = CreateMessage(0x18FECAFE, isExtended: true, dlc: 8);
            message.OverrideSa = 0x11;

            // Act
            byte[] frame = UsrFrameBuilder.Build13Bytes(message);

            // Assert: bytes 1-4 encode the CAN ID with SA substituted
            // Expected ID: 0x18FECA11
            Assert.AreEqual((byte)0x18, frame[1], "byte[1] = priority+DP+PDU-Format high");
            Assert.AreEqual((byte)0xFE, frame[2], "byte[2] = PDU Format");
            Assert.AreEqual((byte)0xCA, frame[3], "byte[3] = PDU Specific");
            Assert.AreEqual((byte)0x11, frame[4], "byte[4] = SA (overridden)");
        }

        [TestMethod]
        public void Build13Bytes_WithoutOverrideSa_KeepsOriginalSa()
        {
            // Arrange: DBC ID = 0x18FECAFE, no override
            var message = CreateMessage(0x18FECAFE, isExtended: true, dlc: 8);
            message.OverrideSa = null; // explicit null – same as default

            byte[] frame = UsrFrameBuilder.Build13Bytes(message);

            Assert.AreEqual((byte)0xFE, frame[4], "byte[4] should be original SA 0xFE");
        }

        [TestMethod]
        public void Build13Bytes_OverrideSa_DoesNotAffectStandardCanId()
        {
            // Standard (11-bit) messages must never have SA substitution applied
            // even if OverrideSa is mistakenly set (guard against future misuse).
            var message = CreateMessage(0x123, isExtended: false, dlc: 8);
            message.OverrideSa = 0xAB; // should be ignored for standard frames

            byte[] frame = UsrFrameBuilder.Build13Bytes(message);

            // CAN ID 0x00000123: bytes 1=0x00, 2=0x00, 3=0x01, 4=0x23
            Assert.AreEqual((byte)0x23, frame[4], "SA override must be ignored for standard frames");
        }

        [TestMethod]
        public void Build13BytesForMuxGroup_WithOverrideSa_ReplacesLowByte()
        {
            // Arrange multiplexed message with SA override
            var muxorSignal = new SignalTxState
            {
                Signal = CreateSignal(0, 4, true, false),
                RawValue = 0,
                PhysicalValue = 0,
                IsMuted = false,
                Error = null
            };
            var groupSignal = new SignalTxState
            {
                Signal = CreateSignal(8, 8, true, false),
                RawValue = 0xBB,
                PhysicalValue = 0xBB,
                IsMuted = false,
                Error = null
            };

            var message = CreateMessage(0x18FECA00, isExtended: true, dlc: 8);
            message.OverrideSa = 0x55;
            message.MultiplexorSignal = muxorSignal;
            var group = new MultiplexGroup { MuxValue = 1 };
            group.Signals.Add(groupSignal);
            message.MultiplexGroups = new System.Collections.Generic.SortedDictionary<int, MultiplexGroup>
            {
                [1] = group
            };

            byte[] frame = UsrFrameBuilder.Build13BytesForMuxGroup(message, 1);

            Assert.AreEqual((byte)0x55, frame[4], "Mux group frame must also apply SA override");
        }
    }
}
