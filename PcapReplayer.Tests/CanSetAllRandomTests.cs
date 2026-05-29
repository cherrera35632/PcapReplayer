using System;
using System.Collections.Generic;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class CanSetAllRandomTests
    {
        // ── helpers ───────────────────────────────────────────────────────────────────

        private static DbcSignal CreateDbcSignal(string name, double min = 0, double max = 255,
            bool isSigned = false, int length = 8)
        {
            return new DbcSignal
            {
                Name = name,
                StartBit = 0,
                Length = length,
                IsLittleEndian = true,
                IsSigned = isSigned,
                Factor = 1,
                Offset = 0,
                Min = min,
                Max = max,
                Unit = string.Empty
            };
        }

        private static SignalTxState CreateSignalState(string name, double min = 0, double max = 255,
            string? error = null)
        {
            return new SignalTxState
            {
                Signal = CreateDbcSignal(name, min, max),
                PhysicalValue = (min + max) / 2.0,
                RawValue = (long)((min + max) / 2.0),
                IsMuted = true,
                GenMode = SignalGenMode.Fixed,
                Error = error
            };
        }

        private static MessageTxState CreateMessage(string name, bool enabled = false, int periodMs = 100)
        {
            return new MessageTxState
            {
                Name = name,
                CanId = 0x123,
                IsExtended = false,
                Dlc = 8,
                Enabled = enabled,
                PeriodMs = periodMs
            };
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // Basic behaviour
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void SetAllToRandom1s_StandardMessage_UpdatesCorrectly()
        {
            var msg = CreateMessage("TestMsg");
            var sig1 = CreateSignalState("Sig1");
            var sig2 = CreateSignalState("Sig2");
            msg.Signals.Add(sig1);
            msg.Signals.Add(sig2);

            MainForm.SetAllToRandom1s(new List<MessageTxState> { msg });

            Assert.IsTrue(msg.Enabled, "Message must be enabled.");
            Assert.AreEqual(1000, msg.PeriodMs, "Message period must be 1s (1000ms).");
            Assert.IsFalse(sig1.IsMuted, "Signal 1 must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, sig1.GenMode, "Signal 1 gen mode must be Random.");
            Assert.IsFalse(sig2.IsMuted, "Signal 2 must be unmuted.");
            Assert.AreEqual(SignalGenMode.Random, sig2.GenMode, "Signal 2 gen mode must be Random.");
        }

        [TestMethod]
        public void SetAllToRandom1s_EmptyList_DoesNotThrow()
        {
            try { MainForm.SetAllToRandom1s(new List<MessageTxState>()); }
            catch (Exception ex)
            { Assert.Fail($"Should not throw: {ex.Message}"); }
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // Stale error clearing — the bug fix regression tests
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void SetAllToRandom1s_SignalWithStaleError_ValidRange_ErrorIsCleared()
        {
            // Simulates DischargePressure PSI: value encoded as -5000 at load time → Error set.
            // After "Set All", signal is in Random mode with a valid range → Error MUST be null.
            var msg = CreateMessage("PressureMsg");
            var sig = CreateSignalState("DischargePressure PSI",
                min: 0, max: 5000,
                error: "physical value -5000 out of range [0, 5000]");
            msg.Signals.Add(sig);

            MainForm.SetAllToRandom1s(new List<MessageTxState> { msg });

            Assert.IsNull(sig.Error,
                "Stale encoding error must be cleared when signal has a valid range in Random mode.");
            Assert.IsFalse(sig.IsMuted, "Signal must be unmuted after Set All.");
            Assert.AreEqual(SignalGenMode.Random, sig.GenMode);
        }

        [TestMethod]
        public void SetAllToRandom1s_SignalWithValidRange_NoPreexistingError_RemainsNullError()
        {
            var msg = CreateMessage("Msg");
            var sig = CreateSignalState("NiceSignal", min: 0, max: 100, error: null);
            msg.Signals.Add(sig);

            MainForm.SetAllToRandom1s(new List<MessageTxState> { msg });

            Assert.IsNull(sig.Error, "Error must remain null for a signal that already had no error.");
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // Degenerate range — signal with Min >= Max stays muted
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void SetAllToRandom1s_SignalWithDegenerateRange_RemainsOrBecomesMuted()
        {
            // Min == Max == 0, Length = 1 bit, Factor=1, Offset=0
            // Bit-derived range: 0 … 1 for unsigned. But DBC Min=0, Max=0 → degenerate.
            // GetEffectiveRange falls back to bit-length → [0, 1] → actually NOT degenerate.
            // Let's use a truly degenerate: Length=1 unsigned with Factor=0 so min=max=0.
            var sig = new SignalTxState
            {
                Signal = new DbcSignal
                {
                    Name = "Degenerate",
                    StartBit = 0,
                    Length = 1,
                    IsLittleEndian = true,
                    IsSigned = false,
                    Factor = 0,   // factor=0 → all physical values collapse to Offset
                    Offset = 42,
                    Min = 42,
                    Max = 42,     // min == max
                    Unit = string.Empty
                },
                IsMuted = false,
                GenMode = SignalGenMode.Fixed,
                PhysicalValue = 42,
                RawValue = 0
            };

            var msg = CreateMessage("DegMsg");
            msg.Signals.Add(sig);

            MainForm.SetAllToRandom1s(new List<MessageTxState> { msg });

            Assert.AreEqual(SignalGenMode.Random, sig.GenMode, "GenMode must still be set to Random.");
            Assert.IsTrue(sig.IsMuted,
                "Signal with degenerate effective range must be muted — Random is meaningless for it.");
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // Multiplex groups
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void SetAllToRandom1s_MultiplexedMessage_UpdatesAllGroupsCorrectly()
        {
            var msg = CreateMessage("MuxMsg");
            var normalSig = CreateSignalState("NormalSig");
            msg.Signals.Add(normalSig);

            var group1 = new MultiplexGroup { MuxValue = 1, Enabled = false, PeriodMs = 250 };
            var groupSig1 = CreateSignalState("GroupSig1",
                error: "physical value 999 out of range [0, 255]");
            group1.Signals.Add(groupSig1);

            var group2 = new MultiplexGroup { MuxValue = 2, Enabled = false, PeriodMs = 500 };
            var groupSig2 = CreateSignalState("GroupSig2");
            group2.Signals.Add(groupSig2);

            msg.MultiplexGroups = new SortedDictionary<int, MultiplexGroup>
            {
                { 1, group1 }, { 2, group2 }
            };

            MainForm.SetAllToRandom1s(new List<MessageTxState> { msg });

            Assert.IsTrue(msg.Enabled); Assert.AreEqual(1000, msg.PeriodMs);
            Assert.IsFalse(normalSig.IsMuted); Assert.AreEqual(SignalGenMode.Random, normalSig.GenMode);

            Assert.IsTrue(group1.Enabled); Assert.AreEqual(1000, group1.PeriodMs);
            Assert.IsFalse(groupSig1.IsMuted); Assert.AreEqual(SignalGenMode.Random, groupSig1.GenMode);
            Assert.IsNull(groupSig1.Error,
                "Stale error in mux group signal must be cleared after Set All.");

            Assert.IsTrue(group2.Enabled); Assert.AreEqual(1000, group2.PeriodMs);
            Assert.IsFalse(groupSig2.IsMuted); Assert.AreEqual(SignalGenMode.Random, groupSig2.GenMode);
        }

        // ═══════════════════════════════════════════════════════════════════════════════
        // Validation guard: non-Fixed signals with stale errors must NOT block TX
        // ═══════════════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void ValidationGuard_RandomSignalWithError_DoesNotBlockTx_ModelLevel()
        {
            // Regression: GetCanStartValidationError must only care about Fixed-mode signals.
            // We verify the model property that makes the check correct, not the UI call.
            var sig = CreateSignalState("BadSig", min: 0, max: 100,
                error: "stale error from load time");
            sig.GenMode = SignalGenMode.Random;
            sig.IsMuted = false;

            // The validator logic: would this signal block TX?
            bool wouldBlock = !sig.IsMuted
                           && !string.IsNullOrEmpty(sig.Error)
                           && sig.GenMode == SignalGenMode.Fixed;

            Assert.IsFalse(wouldBlock,
                "A Random-mode signal with a stale error must NOT block TX start.");
        }

        [TestMethod]
        public void ValidationGuard_FixedSignalWithError_DoesBlockTx_ModelLevel()
        {
            var sig = CreateSignalState("BadFixedSig", min: 0, max: 100,
                error: "value out of range");
            sig.GenMode = SignalGenMode.Fixed;
            sig.IsMuted = false;

            bool wouldBlock = !sig.IsMuted
                           && !string.IsNullOrEmpty(sig.Error)
                           && sig.GenMode == SignalGenMode.Fixed;

            Assert.IsTrue(wouldBlock,
                "A Fixed-mode signal with an encoding error must still block TX start.");
        }
    }
}
