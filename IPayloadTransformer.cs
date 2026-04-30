namespace PcapReplayer
{
    /// <summary>
    /// Transforms a raw UDP payload before it is sent during replay.
    ///
    /// Rationale — Open/Closed and Dependency Inversion:
    /// <see cref="ReplayEngine"/> does not know or care what kind of transformation
    /// is applied. Callers inject the appropriate implementation:
    ///
    ///   • <see cref="UsrMetadataTransformer"/> — replaces the pipe-delimited ASCII
    ///     header in USR-CANET200 packets. One instance per simulated asset, each
    ///     constructed with the asset's specific identity string.
    ///
    ///   • Future: PeakMetadataTransformer, CanIdRemapTransformer, etc.
    ///
    /// Multi-asset CLI scenario:
    /// <code>
    ///   // site.json drives this — one transformer per asset
    ///   var pump1 = new UsrMetadataTransformer("PUMP-001|P|R|J0|C1");
    ///   var pump2 = new UsrMetadataTransformer("PUMP-002|P|R|J0|C1");
    ///   var tasks = new[]
    ///   {
    ///       engine1.RunAsync(new ReplayConfig("pump1.pcap", ..., pump1)),
    ///       engine2.RunAsync(new ReplayConfig("pump2.pcap", ..., pump2)),
    ///   };
    ///   await Task.WhenAll(tasks);
    /// </code>
    /// </summary>
    public interface IPayloadTransformer
    {
        /// <summary>
        /// Attempts to transform <paramref name="payload"/>.
        /// </summary>
        /// <param name="payload">Original UDP payload bytes to inspect and potentially modify.</param>
        /// <param name="transformed">
        /// The bytes to send. Set to <paramref name="payload"/> when no modification is made.
        /// </param>
        /// <returns><c>true</c> if the payload was modified and <paramref name="transformed"/>
        /// differs from <paramref name="payload"/>; <c>false</c> otherwise.</returns>
        bool TryTransform(byte[] payload, out byte[] transformed);
    }

    /// <summary>
    /// A no-op transformer — passes every payload through unchanged.
    /// Used when no metadata override is configured so the engine's hot path
    /// still delegates through the same interface without a null check.
    /// </summary>
    public sealed class NullTransformer : IPayloadTransformer
    {
        /// <summary>Shared singleton — stateless, safe for all callers.</summary>
        public static readonly NullTransformer Instance = new();

        private NullTransformer() { }

        public bool TryTransform(byte[] payload, out byte[] transformed)
        {
            transformed = payload;
            return false;
        }
    }

    /// <summary>
    /// Replaces the pipe-delimited ASCII metadata header in USR-CANET200 packets
    /// with <see cref="OverrideString"/> before each packet is sent.
    /// Non-USR packets (PEAK, unclassified) are passed through verbatim.
    /// </summary>
    public sealed class UsrMetadataTransformer : IPayloadTransformer
    {
        /// <summary>The identity string to inject, e.g. <c>"PUMP-001|P|R|J0|C1|3"</c>.</summary>
        public string OverrideString { get; }

        public UsrMetadataTransformer(string overrideString)
        {
            if (string.IsNullOrWhiteSpace(overrideString))
                throw new ArgumentException("Override string must not be null or whitespace.", nameof(overrideString));
            OverrideString = overrideString;
        }

        public bool TryTransform(byte[] payload, out byte[] transformed)
        {
            // Only classify and inject when this really is a USR packet.
            // PEAK / unclassified → pass through with zero allocation.
            if (!UsrPacketHelper.IsUsrPacket(payload, out _))
            {
                transformed = payload;
                return false;
            }

            transformed = UsrPacketHelper.InjectUsrMetadata(payload, OverrideString);
            return true;
        }
    }
}
