using System;
using System.Threading;
using System.Threading.Tasks;

namespace PcapReplayer
{
    public interface ICanTransmitter
    {
        event Action<string>? OnLog;
        event Action<int>? OnTxCount;
        event Action<Exception>? OnError;

        Task StartAsync(CanGenConfig cfg, CancellationToken ct);
        void Stop();
    }
}
