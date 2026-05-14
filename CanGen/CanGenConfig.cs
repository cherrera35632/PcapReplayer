using System.Collections.Generic;

namespace PcapReplayer
{
    public sealed record CanGenConfig(
        string TargetIp,
        int TargetPort,
        string SourceIp,
        string UsrMetadataHeader,
        IReadOnlyList<MessageTxState> Messages);
}
