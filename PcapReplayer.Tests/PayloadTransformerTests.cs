using System;
using System.Text;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using PcapReplayer;

namespace PcapReplayer.Tests
{
    /// <summary>
    /// Unit tests for <see cref="IPayloadTransformer"/> implementations:
    /// <see cref="NullTransformer"/> and <see cref="UsrMetadataTransformer"/>.
    ///
    /// These tests protect the transformer contract and ensure the multi-asset
    /// CLI scenario (one transformer instance per simulated asset) behaves correctly
    /// and independently.
    /// </summary>
    [TestClass]
    public class PayloadTransformerTests
    {
        // ── Helpers ───────────────────────────────────────────────────────────
        private static byte[] Ascii(string s) => Encoding.ASCII.GetBytes(s);

        private static byte[] PeakFrame() => new byte[] { 0x00, 0x04, 0x80, 0x00 };

        private static byte[] UsrMeta(string s) => Ascii(s);

        private static byte[] UsrMixed(string header)
        {
            byte[] h = Ascii(header);
            var    f = new byte[13];
            f[0] = 0x88; // non-ASCII info byte
            f[1] = 0x18; f[2] = 0xFE; f[3] = 0xF1; f[4] = 0x00;
            var result = new byte[h.Length + f.Length];
            Buffer.BlockCopy(h, 0, result, 0, h.Length);
            Buffer.BlockCopy(f, 0, result, h.Length, f.Length);
            return result;
        }

        // ══════════════════════════════════════════════════════════════════════
        //  NullTransformer Tests
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void NullTransformer_AlwaysReturnsFalse()
        {
            byte[] payload = Ascii("PUMP|P|R|J0|C1");
            bool   changed = NullTransformer.Instance.TryTransform(payload, out byte[] result);

            Assert.IsFalse(changed);
        }

        [TestMethod]
        public void NullTransformer_OutPayloadIsSameReference()
        {
            byte[] payload = Ascii("ANY_DATA");
            NullTransformer.Instance.TryTransform(payload, out byte[] result);

            // NullTransformer must not allocate — it should hand back the same reference
            Assert.AreSame(payload, result,
                "NullTransformer must return the original array reference to avoid allocation.");
        }

        [TestMethod]
        public void NullTransformer_IsSingleton()
        {
            var a = NullTransformer.Instance;
            var b = NullTransformer.Instance;
            Assert.AreSame(a, b, "NullTransformer.Instance must always return the same object.");
        }

        [TestMethod]
        public void NullTransformer_WorksOnEmptyPayload()
        {
            bool changed = NullTransformer.Instance.TryTransform(Array.Empty<byte>(), out byte[] result);
            Assert.IsFalse(changed);
            Assert.AreEqual(0, result.Length);
        }

        // ══════════════════════════════════════════════════════════════════════
        //  UsrMetadataTransformer — Construction
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void UsrMetadataTransformer_NullString_Throws()
            => _ = new UsrMetadataTransformer(null!);

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void UsrMetadataTransformer_EmptyString_Throws()
            => _ = new UsrMetadataTransformer(string.Empty);

        [TestMethod]
        [ExpectedException(typeof(ArgumentException))]
        public void UsrMetadataTransformer_WhitespaceString_Throws()
            => _ = new UsrMetadataTransformer("   ");

        [TestMethod]
        public void UsrMetadataTransformer_ValidString_SetsProperty()
        {
            const string s = "PUMP-001|P|R|J0|C1|3";
            var t = new UsrMetadataTransformer(s);
            Assert.AreEqual(s, t.OverrideString);
        }

        // ══════════════════════════════════════════════════════════════════════
        //  UsrMetadataTransformer — Transform behaviour
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void UsrMetadataTransformer_UsrPureMetadataPayload_ReturnsTrue_OverridesContent()
        {
            const string newMeta = "PUMP-002|P|R|J0|C1|3";
            var t       = new UsrMetadataTransformer(newMeta);
            byte[] payload = UsrMeta("PUMP-001|P|R|J0|C1|3");

            bool changed = t.TryTransform(payload, out byte[] result);

            Assert.IsTrue(changed);
            Assert.AreEqual(newMeta, Encoding.ASCII.GetString(result));
        }

        [TestMethod]
        public void UsrMetadataTransformer_UsrMixedPayload_ReturnsTrue_OverridesHeaderPreservesBinary()
        {
            const string originalHeader = "PUMP-001|P|R|J0|C1";
            const string newMeta        = "PUMP-XYZ|P|R|J0|C2|3";
            var t = new UsrMetadataTransformer(newMeta);

            byte[] payload = UsrMixed(originalHeader);
            int    binaryLen = payload.Length - Ascii(originalHeader).Length;

            bool changed = t.TryTransform(payload, out byte[] result);

            Assert.IsTrue(changed, "A USR mixed packet must be transformed.");
            string resultHeader = Encoding.ASCII.GetString(result, 0, newMeta.Length);
            Assert.AreEqual(newMeta, resultHeader, "Header must be replaced.");
            Assert.AreEqual(newMeta.Length + binaryLen, result.Length, "Binary section length must be preserved.");
        }

        [TestMethod]
        public void UsrMetadataTransformer_PeakPayload_ReturnsFalse_PassesThrough()
        {
            var t = new UsrMetadataTransformer("PUMP-001|P|R|J0|C1");
            byte[] peak = PeakFrame();

            bool changed = t.TryTransform(peak, out byte[] result);

            Assert.IsFalse(changed, "PEAK payload must be passed through without modification.");
            Assert.AreSame(peak, result, "Reference must be the same for unmodified payloads — no allocation.");
        }

        [TestMethod]
        public void UsrMetadataTransformer_EmptyPayload_ReturnsFalse()
        {
            var t = new UsrMetadataTransformer("PUMP-001|P|R|J0|C1");
            bool changed = t.TryTransform(Array.Empty<byte>(), out byte[] result);
            Assert.IsFalse(changed);
        }

        [TestMethod]
        public void UsrMetadataTransformer_UnclassifiablePayload_ReturnsFalse()
        {
            var t = new UsrMetadataTransformer("PUMP-001|P|R|J0|C1");
            byte[] noise = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };
            bool changed = t.TryTransform(noise, out _);
            Assert.IsFalse(changed, "Unclassifiable payload must not be transformed.");
        }

        // ══════════════════════════════════════════════════════════════════════
        //  Multi-asset independence — critical for the CLI site-simulation scenario
        // ══════════════════════════════════════════════════════════════════════

        [TestMethod]
        public void MultipleTransformers_AreIndependent_DontInterfer()
        {
            // Simulates 3 concurrent assets from site.json:
            //   pump1, pump2, blender — each with its own override string.
            var pump1   = new UsrMetadataTransformer("PUMP-001|P|R|J0|C1|3");
            var pump2   = new UsrMetadataTransformer("PUMP-002|P|R|J0|C1|3");
            var blender = new UsrMetadataTransformer("BLEND-01|B|R|NB0|C1|1");

            byte[] sharedPayload = UsrMeta("ORIG|P|R|J0|C1");

            pump1.TryTransform(sharedPayload,   out byte[] r1);
            pump2.TryTransform(sharedPayload,   out byte[] r2);
            blender.TryTransform(sharedPayload, out byte[] r3);

            Assert.AreEqual("PUMP-001|P|R|J0|C1|3", Encoding.ASCII.GetString(r1));
            Assert.AreEqual("PUMP-002|P|R|J0|C1|3", Encoding.ASCII.GetString(r2));
            Assert.AreEqual("BLEND-01|B|R|NB0|C1|1", Encoding.ASCII.GetString(r3));

            // Original payload is never modified (immutability invariant)
            Assert.AreEqual("ORIG|P|R|J0|C1", Encoding.ASCII.GetString(sharedPayload));
        }

        [TestMethod]
        public void MultipleTransformers_SamePayloadClass_DifferentOutputs()
        {
            // Regression: two transformers acting on the same payload byte[] must
            // produce independently correct outputs and not alias each other's buffers.
            var t1 = new UsrMetadataTransformer("ASSET-A|P|R|J0|C1");
            var t2 = new UsrMetadataTransformer("ASSET-B|P|R|J0|C2");

            byte[] payload = UsrMeta("ORIGINAL|P|R|J0|C1");

            t1.TryTransform(payload, out byte[] out1);
            t2.TryTransform(payload, out byte[] out2);

            // The two outputs must not be the same reference
            Assert.AreNotSame(out1, out2);
            Assert.AreEqual("ASSET-A|P|R|J0|C1", Encoding.ASCII.GetString(out1));
            Assert.AreEqual("ASSET-B|P|R|J0|C2", Encoding.ASCII.GetString(out2));
        }
    }
}
