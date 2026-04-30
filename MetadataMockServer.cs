using System;
using System.Net;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace PcapReplayer
{
    /// <summary>
    /// Lightweight config snapshot captured from the UI at each request,
    /// so field edits take effect immediately without restarting the server.
    /// </summary>
    public record MockServerConfig(
        int Port,
        string ProductName,
        string OrderNo,
        string DeviceName,
        int CanCount,
        string ChannelName,
        int Bitrate,
        int Active,
        int ListenOnly,
        bool RespondToRequests);

    /// <summary>
    /// Embeds a System.Net.HttpListener that mocks the PEAK CAN Gateway
    /// metadata endpoints consumed by UDPCANGateway.
    /// </summary>
    public class MetadataMockServer
    {
        // Events raised on arbitrary thread-pool threads — callers must marshal to UI.
        public event Action<string>? OnRequestLogged;
        public event Action<string>? OnStatusChanged;

        // Delegate invoked at each request to get the current UI values.
        private Func<MockServerConfig>? _getConfig;

        private HttpListener? _listener;
        private CancellationTokenSource? _cts;
        private Task? _loopTask;

        public bool IsRunning => _listener?.IsListening == true;

        /// <summary>Start listening. <paramref name="getConfig"/> is called once per request.</summary>
        public void Start(int port, string listenerIp, Func<MockServerConfig> getConfig)
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

            string statusMsg = $"Listening on {listenerIp}:{port}";
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

                // Handle without awaiting so the loop picks up the next request immediately.
                _ = Task.Run(() => HandleRequest(ctx), ct);
            }
        }

        private void HandleRequest(HttpListenerContext ctx)
        {
            var config = _getConfig?.Invoke();
            var req = ctx.Request;
            var res = ctx.Response;

            string url = req.Url?.PathAndQuery ?? "/";
            string cmd = req.QueryString["cmd"] ?? "";
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
                (statusCode, body) = BuildResponse(cmd, config);
            }

            byte[] bytes = Encoding.UTF8.GetBytes(body);
            res.StatusCode = statusCode;
            res.ContentType = "application/json";
            res.ContentLength64 = bytes.Length;

            try
            {
                if (bytes.Length > 0)
                    res.OutputStream.Write(bytes, 0, bytes.Length);
                res.OutputStream.Close();
            }
            catch { /* client disconnected */ }

            string statusText = statusCode == 200 ? "200 OK" : statusCode.ToString();
            string logLine = $"[{timestamp}]  {req.HttpMethod} {url}  ->  {statusText}";
            OnRequestLogged?.Invoke(logLine);
        }

        private static (int statusCode, string body) BuildResponse(string cmd, MockServerConfig cfg)
        {
            // Normalise: query strings arrive URL-decoded already, so "get+device" stays "get device"
            cmd = cmd.Trim().ToLowerInvariant();

            if (cmd == "get device")
            {
                string json = $@"{{
  ""valid"": true,
  ""error"": 0,
  ""error_message"": """",
  ""product_name"": ""{Escape(cfg.ProductName)}"",
  ""order_no"": ""{Escape(cfg.OrderNo)}"",
  ""serial_no"": 12345,
  ""hardware_version"": ""1.0"",
  ""software_version"": ""1.5"",
  ""website_version"": ""1.0"",
  ""interface_version"": ""1.0"",
  ""CAN_count"": {cfg.CanCount},
  ""LAN_count"": 1,
  ""WLAN_count"": 0,
  ""name"": ""{Escape(cfg.DeviceName)}"",
  ""description"": ""Mock PEAK Gateway"",
  ""can_fd_support"": false
}}";
                return (200, json);
            }

            if (cmd.StartsWith("get can "))
            {
                string idxStr = cmd["get can ".Length..].Trim();
                if (int.TryParse(idxStr, out int idx))
                {
                    // IMPORTANT: must be compact/minified JSON (no newlines, no extra spaces).
                    // UDPCANGateway does: rsp.Replace($",\"{idx}\":{{\"channel", ",\"detail\":{\"channel")
                    // That pattern only matches when the JSON is on a single line.
                    string json = $"{{\"valid\":true,\"error\":0,\"error_message\":\"\",\"{idx}\":{{\"channel\":{idx},\"active\":{cfg.Active},\"status\":0,\"bitrate\":{cfg.Bitrate},\"listen_only\":{cfg.ListenOnly},\"user_notes\":\"{Escape(cfg.ChannelName)}\"}}}}";
                    return (200, json);
                }
            }

            // Unknown command
            return (404, @"{""valid"":false,""error"":1,""error_message"":""Unknown command""}");
        }

        /// <summary>Minimal JSON string escaping.</summary>
        private static string Escape(string s) =>
            s.Replace("\\", "\\\\").Replace("\"", "\\\"");
    }
}
