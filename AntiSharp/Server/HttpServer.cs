using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Sockets;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using AntiSharp.Core;
using AntiSharp.Logger;
using AntiSharp.Events;

namespace AntiSharp.Server
{
    public class HttpServer
    {
        private readonly TcpListener listener;
        private readonly ServerEvent eventHandler;
        private readonly ServerLogs logger;
        private readonly ClientEvent clientEvent;
        public HttpServer(int port)
        {
            listener = new TcpListener(IPAddress.Any, port);
            eventHandler = new ServerEvent();
            logger = new ServerLogs();
            clientEvent = new ClientEvent();
        }

        public async Task StartAsync()
        {
            listener.Start();
            await logger.LogAsync($"Server started on port {((IPEndPoint)listener.LocalEndpoint).Port}", ServerLogs.LogLevel.Info);

            while (true)
            {
                try
                {
                    TcpClient client = await listener.AcceptTcpClientAsync();
                    var clientIP = ((IPEndPoint)client.Client.RemoteEndPoint).Address;

                    if (eventHandler.IsAllowed(clientIP, true))
                    {
                        await logger.LogAsync($"New connection accepted from {clientIP}", ServerLogs.LogLevel.Info);
                        _ = HandleClientAsync(client);
                    }
                    else
                    {
                        await logger.LogAsync($"Connection blocked from {clientIP} (DDoS protection)", ServerLogs.LogLevel.Security);
                        client.Close();
                    }
                }
                catch (Exception ex)
                {
                    await logger.LogAsync($"Error accepting client: {ex.Message}", ServerLogs.LogLevel.Error);
                }
            }
        }
        private string ExtractUserAgent(string request)
        {
            var lines = request.Split('\n');
            foreach (var line in lines)
            {
                if (line.StartsWith("User-Agent:", StringComparison.OrdinalIgnoreCase))
                {
                    return line.Substring("User-Agent:".Length).Trim();
                }
            }
            return string.Empty;
        }
        private async Task HandleClientAsync(TcpClient client)
        {
            var clientIP = ((IPEndPoint)client.Client.RemoteEndPoint).Address;

            try
            {

                using NetworkStream stream = client.GetStream();
                byte[] buffer = new byte[1024];
                int bytesRead = await stream.ReadAsync(buffer, 0, buffer.Length);

                string request = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                string userAgent = ExtractUserAgent(request);

                if (!clientEvent.IsAllowed(clientIP, userAgent, ClientEvent.ProtectionType.HTTP))
                {
                    await logger.LogAsync($"Blocked suspicious activity from {clientIP}", ServerLogs.LogLevel.Security);
                    return;
                }
                string response = "HTTP/1.1 200 OK\r\n" +
                                "Content-Type: text/html\r\n" +
                                "Connection: close\r\n" +
                                "\r\n" +
                                "<html><body><h1>Hello from AntiSharp HTTP Server!</h1></body></html>";

                byte[] responseData = Encoding.UTF8.GetBytes(response);
                await stream.WriteAsync(responseData, 0, responseData.Length);
                await logger.LogAsync($"Sent response to {clientIP}", ServerLogs.LogLevel.Info);
            }
            catch (Exception ex)
            {
                await logger.LogAsync($"Error handling client {clientIP}: {ex.Message}", ServerLogs.LogLevel.Error);
            }
            finally
            {
                eventHandler.ReleaseConnection(clientIP);
                await logger.LogAsync($"Connection closed for {clientIP}", ServerLogs.LogLevel.Info);
                client.Close();
            }
        }
    }
}
