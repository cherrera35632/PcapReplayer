using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace PcapReplayer.Tests
{
    [TestClass]
    public class SignalValueGeneratorTests
    {
        // ── helpers ──────────────────────────────────────────────────────────────────────

        private static SignalTxState CreateSignal(double min, double max,
            SignalGenMode mode = SignalGenMode.Fixed, int sinePeriodMs = 1000, double factor = 1)
        {
            var signal = new SignalTxState
            {
                Signal = new DbcSignal
                {
                    Name           = "TestSig",
                    StartBit       = 0,
                    Length         = 16,
                    IsLittleEndian = true,
                    IsSigned       = false,
                    Factor         = factor,
                    Offset         = 0,
                    Min            = min,
                    Max            = max,
                    Unit           = string.Empty
                },
                PhysicalValue = (min + max) / 2.0,
                RawValue      = (long)((min + max) / 2.0),
                IsMuted       = false,
                GenMode       = mode,
                SinePeriodMs  = sinePeriodMs
            };
            return signal;
        }

        // ── Fixed mode ────────────────────────────────────────────────────────────────────

        [TestMethod]
        public void Update_FixedMode_DoesNotChangeValue()
        {
            var signal = CreateSignal(0, 100, SignalGenMode.Fixed);
            double original = signal.PhysicalValue;

            SignalValueGenerator.Update(signal, 1.0);

            Assert.AreEqual(original, signal.PhysicalValue, "Fixed mode must not change PhysicalValue");
        }

        [TestMethod]
        public void Update_MutedSignal_DoesNotChangeValue()
        {
            var signal = CreateSignal(0, 100, SignalGenMode.Random);
            signal.IsMuted = true;
            double original = signal.PhysicalValue;

            SignalValueGenerator.Update(signal, 1.0);

            Assert.AreEqual(original, signal.PhysicalValue, "Muted signals must not be updated");
        }

        // ── Random mode ───────────────────────────────────────────────────────────────────

        [TestMethod]
        public void Update_RandomMode_StaysWithinRange()
        {
            var signal = CreateSignal(10, 200, SignalGenMode.Random);

            for (int i = 0; i < 500; i++)
            {
                SignalValueGenerator.Update(signal, i * 0.1);
                Assert.IsTrue(signal.PhysicalValue >= 10 && signal.PhysicalValue <= 200,
                    $"PhysicalValue {signal.PhysicalValue} is outside [10, 200]");
            }
        }

        [TestMethod]
        public void Update_RandomMode_ProducesVariation()
        {
            var signal = CreateSignal(0, 1000, SignalGenMode.Random);
            double first = double.NaN;
            bool sawDifferent = false;

            for (int i = 0; i < 100; i++)
            {
                SignalValueGenerator.Update(signal, i * 0.01);
                if (i == 0) { first = signal.PhysicalValue; continue; }
                if (Math.Abs(signal.PhysicalValue - first) > 0.001) { sawDifferent = true; break; }
            }

            Assert.IsTrue(sawDifferent, "Random mode should produce different values across ticks");
        }

        // ── Sine mode ─────────────────────────────────────────────────────────────────────

        [TestMethod]
        public void Update_SineMode_StaysWithinRange()
        {
            var signal = CreateSignal(-50, 50, SignalGenMode.Sine, sinePeriodMs: 1000);

            for (int i = 0; i < 1000; i++)
            {
                SignalValueGenerator.Update(signal, i * 0.001);
                Assert.IsTrue(signal.PhysicalValue >= -50 && signal.PhysicalValue <= 50,
                    $"Sine value {signal.PhysicalValue} at t={i * 0.001:F3}s is outside [-50, 50]");
            }
        }

        [TestMethod]
        public void Update_SineMode_OscillatesAroundMidpoint()
        {
            // At t=0 sin(0)=0 → value should be midpoint
            var signal = CreateSignal(0, 100, SignalGenMode.Sine, sinePeriodMs: 2000);
            SignalValueGenerator.Update(signal, 0.0);
            Assert.AreEqual(50.0, signal.PhysicalValue, 1.0,
                "At t=0 sine value should equal midpoint (50)");
        }

        [TestMethod]
        public void Update_SineMode_ReachesMaxAtQuarterPeriod()
        {
            // sin(2π * T/4 / T) = sin(π/2) = 1 → value should be max
            var signal = CreateSignal(0, 100, SignalGenMode.Sine, sinePeriodMs: 1000);
            SignalValueGenerator.Update(signal, 0.25); // quarter period = 0.25 s
            Assert.AreEqual(100.0, signal.PhysicalValue, 1.0,
                "At t=T/4 sine value should reach max (100)");
        }

        // ── Degenerate range ──────────────────────────────────────────────────────────────

        [TestMethod]
        public void Update_DegenerateRange_DoesNotChangeValue()
        {
            var signal = CreateSignal(42, 42, SignalGenMode.Random, factor: 0); // min == max and factor == 0 makes it degenerate
            double original = signal.PhysicalValue;

            SignalValueGenerator.Update(signal, 1.0);

            Assert.AreEqual(original, signal.PhysicalValue,
                "Degenerate range (min==max) must not crash or change value");
        }
    }
}
