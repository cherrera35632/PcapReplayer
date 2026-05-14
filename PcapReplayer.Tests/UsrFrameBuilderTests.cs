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
    }
}
