using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PcapReplayer
{
    /// <summary>
    /// Local-only simulation of the "is_dirty" telemetry that, in the field, arrives via
    /// ProxyBox HTTP polling or NOV Container MODBUS — never over CAN, so nothing else in
    /// this tool can generate it. Metric names and label sets intentionally match the real
    /// field format exactly, so a dashboard built against this mock needs no changes once
    /// pointed at the real exporter/datasource.
    /// </summary>
    public record PromMockConfig(
        int Port,
        string AssetId,
        string EquipmentType,
        string Manufacturer,
        string Ip,
        string Crew,
        string District,
        string TmvAssetId,
        string Version,
        bool IsProxyBox,
        int DirtyValue,          // 0 = clean, 1 = dirty, -999 = unknown/offline
        bool RespondToRequests);

    /// <summary>
    /// Embeds a System.Net.HttpListener that serves Prometheus text-exposition format
    /// at "/", mirroring MetadataMockServer's start/stop/config-snapshot pattern.
    /// </summary>
    public class PrometheusMockServer
    {
        // Events raised on arbitrary thread-pool threads — callers must marshal to UI.
        public event Action<string>? OnRequestLogged;
        public event Action<string>? OnStatusChanged;

        // Delegate invoked at each request to get the current UI values.
        private Func<PromMockConfig>? _getConfig;

        private HttpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;

        public bool IsRunning => _listener?.IsListening == true;

        /// <summary>Start listening. <paramref name="getConfig"/> is called once per request.</summary>
        public void Start(int port, string listenerIp, Func<PromMockConfig> getConfig)
        {
            if (IsRunning) return;

            _getConfig = getConfig;
            _cts = new CancellationTokenSource();

            _listener = new HttpListener();
            _listener.Prefixes.Add($"http://{listenerIp}:{port}/");

            try
            {
                _listener.Start();
            }
            catch (Exception ex)
            {
                OnStatusChanged?.Invoke($"Error: {ex.Message}");
                _listener = null;
                return;
            }

            string statusMsg = $"Listening on {listenerIp}:{port}/  (Prometheus scrapes this path)";
            if (port == 80) statusMsg += " (port 80 may require elevated privileges)";
            OnStatusChanged?.Invoke(statusMsg);

            var token = _cts.Token;
            _loopTask = Task.Run(() => ListenLoop(token), token);
        }

        public void Stop()
        {
            if (!IsRunning) return;

            try { _cts?.Cancel(); } catch { }
            try { _listener?.Stop(); } catch { }

            _listener = null;
            OnStatusChanged?.Invoke("Stopped");
        }

        // ── Internal loop ──────────────────────────────────────────────────

        private async Task ListenLoop(CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener!.GetContextAsync().ConfigureAwait(false);
                }
                catch (HttpListenerException) { break; }
                catch (ObjectDisposedException) { break; }
                catch { break; }

                _ = Task.Run(() => HandleRequest(ctx), ct);
            }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            var config = _getConfig?.Invoke();
            var req = ctx.Request;
            var res = ctx.Response;
            string timestamp = DateTime.Now.ToString("HH:mm:ss.fff");

            int statusCode;
            string body;

            if (config == null || !config.RespondToRequests)
            {
                statusCode = 503;
                body = "";
            }
            else
            {
                statusCode = 200;
                body = BuildMetricsBody(config);
            }

            byte[] bytes = Encoding.UTF8.GetBytes(body);
            res.StatusCode = statusCode;
            res.ContentType = "text/plain; version=0.0.4; charset=utf-8";
            res.ContentLength64 = bytes.Length;

            try
            {
                if (bytes.Length > 0)
                    res.OutputStream.Write(bytes, 0, bytes.Length);
                res.OutputStream.Close();
            }
            catch { /* client disconnected */ }

            string statusText = statusCode == 200 ? "200 OK" : statusCode.ToString();
            string logLine = $"[{timestamp}]  {req.HttpMethod} {req.Url?.PathAndQuery}  ->  {statusText}";
            OnRequestLogged?.Invoke(logLine);
        }

        /// <summary>Builds the exact Prometheus exposition text for the currently selected pump flavor.</summary>
        public static string BuildMetricsBody(PromMockConfig c)
        {
            // The real field samples (both ProxyBox and NOV Container) always show
            // equipment_type/mfg in upper case (e.g. "PUMP", "ROLLIGON"), independent of
            // whatever casing the CAN Generator's own USR-header resolver produces
            // ("Pump", "Rolligon") for can_message_counter. Uppercase here to match the
            // real format exactly; the CAN-Generator-cased values are still shown as-is
            // in the Identity preview label so the two can be compared side by side.
            string equipUpper = c.EquipmentType.ToUpperInvariant();
            string mfgUpper = c.Manufacturer.ToUpperInvariant();
            var sb = new StringBuilder();

            if (c.IsProxyBox)
            {
                string routingKey = $"EQ.{equipUpper}.{c.AssetId}.HTTP";
                string url = $"http://{c.Ip}:8000/commands";
                sb.Append("# HELP rolligon_proxybox_config_reported_controller_is_dirty Simulated ProxyBox is_dirty (PcapReplayer mock)\n");
                sb.Append("# TYPE rolligon_proxybox_config_reported_controller_is_dirty untyped\n");
                sb.Append("rolligon_proxybox_config_reported_controller_is_dirty{")
                  .Append($"asset_id=\"{c.AssetId}\",crew=\"{c.Crew}\",district=\"{c.District}\",")
                  .Append($"equipment_type=\"{equipUpper}\",ip=\"{c.Ip}\",mfg=\"{mfgUpper}\",")
                  .Append("port=\"8000\",protocol=\"HTTP\",")
                  .Append($"routing_key=\"{routingKey}\",tmv_asset_id=\"{c.TmvAssetId}\",")
                  .Append($"url=\"{url}\",version=\"{c.Version}\"")
                  .Append($"}} {c.DirtyValue}\n");
            }
            else
            {
                string routingKey = $"EQ.{equipUpper}.{c.AssetId}.MODBUS";
                sb.Append("# HELP pump_rolligon_is_dirty Simulated NOV Container is_dirty (PcapReplayer mock)\n");
                sb.Append("# TYPE pump_rolligon_is_dirty untyped\n");
                sb.Append("pump_rolligon_is_dirty{")
                  .Append($"asset_id=\"{c.AssetId}\",crew=\"{c.Crew}\",district=\"{c.District}\",")
                  .Append($"equipment_type=\"{equipUpper}\",ip=\"{c.Ip}\",mfg=\"{mfgUpper}\",")
                  .Append("port=\"502\",protocol=\"MODBUS\",")
                  .Append($"routing_key=\"{routingKey}\",tmv_asset_id=\"{c.TmvAssetId}\",version=\"{c.Version}\"")
                  .Append($"}} {c.DirtyValue}\n");
            }

            return sb.ToString();
        }
    }
}
