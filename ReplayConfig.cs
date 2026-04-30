namespace PcapReplayer
{
    /// <summary>
    /// All per-asset replay configuration, grouped into a single record.
    ///
    /// This record is the unit of work for the future CLI multi-asset mode:
    /// a JSON site definition deserializes directly into a <c>List&lt;ReplayConfig&gt;</c>,
    /// and a separate <see cref="IPayloadTransformer"/> is constructed per asset
    /// from the JSON's <c>usrOverride</c> / <c>peakOverride</c> fields.
    ///
    /// Current GUI session: <see cref="MainForm"/> builds one instance on Start.
    /// Future CLI session:  a site-loader reads <c>site.json</c> and builds N instances.
    ///
    /// Example site.json (future):
    /// <code>
    /// {
    ///   "assets": [
    ///     { "pcap": "pump1.pcap", "sourceIp": "10.0.0.1", "usrOverride": "PUMP-001|P|R|J0|C1" },
    ///     { "pcap": "pump2.pcap", "sourceIp": "10.0.0.2", "usrOverride": "PUMP-002|P|R|J0|C1" },
    ///     { "pcap": "blend.pcap", "sourceIp": "10.0.0.3", "usrOverride": "BLEND-01|B|R|NB0|C1" }
    ///   ]
    /// }
    /// </code>
    /// </summary>
    /// <param name="PcapFile">Absolute or relative path to the .pcap / .pcapng file.</param>
    /// <param name="TargetIp">Destination IP for replayed UDP packets.</param>
    /// <param name="SourceIp">Source IP to bind the local UDP socket to.</param>
    /// <param name="PortOverride">
    /// Override destination port. Pass <c>-1</c> to inherit the port from each packet's
    /// original destination port in the PCAP.
    /// </param>
    /// <param name="Speed">Replay speed multiplier (1.0 = real-time, 2.0 = double speed).</param>
    /// <param name="Loop">When <c>true</c> the replay loops indefinitely until stopped.</param>
    /// <param name="Transformer">
    /// Optional payload transformer applied per packet before sending.
    /// Pass <see cref="NullTransformer.Instance"/> (or <c>null</c>) for verbatim replay.
    /// </param>
    public record ReplayConfig(
        string              PcapFile,
        string              TargetIp,
        string              SourceIp,
        int                 PortOverride,
        double              Speed,
        bool                Loop,
        IPayloadTransformer? Transformer = null);
}
