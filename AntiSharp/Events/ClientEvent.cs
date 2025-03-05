using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace AntiSharp.Events
{
    public class ClientEvent
    {
        private readonly ConcurrentDictionary<IPAddress, ClientStats> clientStats;
        private readonly ConcurrentDictionary<string, int> userAgentStats;
        private readonly ConcurrentDictionary<IPAddress, long> tcpFloodProtection;
        private readonly ConcurrentDictionary<IPAddress, long> udpFloodProtection;

        private const int MAX_REQUESTS_PER_MINUTE = 300;
        private const int MAX_CONCURRENT_CONNECTIONS = 50;
        private const int BOTNET_THRESHOLD = 1000;
        private const int TCP_FLOOD_THRESHOLD = 500;
        private const int UDP_FLOOD_THRESHOLD = 500;
        private const int SUSPICIOUS_UA_THRESHOLD = 100;
        private const int HTTP_FLOOD_THRESHOLD = 200;

        public ClientEvent()
        {
            clientStats = new ConcurrentDictionary<IPAddress, ClientStats>();
            userAgentStats = new ConcurrentDictionary<string, int>();
            tcpFloodProtection = new ConcurrentDictionary<IPAddress, long>();
            udpFloodProtection = new ConcurrentDictionary<IPAddress, long>();
            StartCleanupTask();
        }

        public class ClientStats
        {
            public int RequestCount { get; set; }
            public DateTime LastRequest { get; set; }
            public int ConcurrentConnections { get; set; }
            public HashSet<string> UserAgents { get; set; } = new HashSet<string>();
            public int FailedRequests { get; set; }
            public int HttpFloodCount { get; set; }
            public DateTime WindowStart { get; set; }
        }

        public bool IsAllowed(IPAddress ip, string userAgent, ProtectionType type)
        {
            var stats = clientStats.GetOrAdd(ip, _ => new ClientStats
            {
                LastRequest = DateTime.UtcNow,
                WindowStart = DateTime.UtcNow
            });

            if ((DateTime.UtcNow - stats.WindowStart).TotalMinutes >= 1)
            {
                stats.RequestCount = 0;
                stats.HttpFloodCount = 0;
                stats.WindowStart = DateTime.UtcNow;
            }

            stats.RequestCount++;
            stats.LastRequest = DateTime.UtcNow;

            switch (type)
            {
                case ProtectionType.HTTP:
                    if (!CheckHttpFlood(stats, userAgent))
                        return false;
                    break;

                case ProtectionType.TCP:
                    if (!CheckTcpFlood(ip))
                        return false;
                    break;

                case ProtectionType.UDP:
                    if (!CheckUdpFlood(ip))
                        return false;
                    break;
            }

            if (IsBotnetActivity(stats, userAgent))
                return false;

            return true;
        }

        private bool CheckHttpFlood(ClientStats stats, string userAgent)
        {
            stats.HttpFloodCount++;

            if (stats.HttpFloodCount > HTTP_FLOOD_THRESHOLD)
                return false;

            if (!string.IsNullOrEmpty(userAgent))
            {
                stats.UserAgents.Add(userAgent);
                userAgentStats.AddOrUpdate(userAgent, 1, (_, count) => count + 1);
            }

            return true;
        }

        private bool CheckTcpFlood(IPAddress ip)
        {
            var count = tcpFloodProtection.AddOrUpdate(ip, 1, (_, c) => c + 1);
            return count <= TCP_FLOOD_THRESHOLD;
        }

        private bool CheckUdpFlood(IPAddress ip)
        {
            var count = udpFloodProtection.AddOrUpdate(ip, 1, (_, c) => c + 1);
            return count <= UDP_FLOOD_THRESHOLD;
        }

        private bool IsBotnetActivity(ClientStats stats, string userAgent)
        {
            if (stats.UserAgents.Count > 10)
                return true;
            if (stats.RequestCount > BOTNET_THRESHOLD)
                return true;
            if (!string.IsNullOrEmpty(userAgent))
            {
                if (userAgentStats.TryGetValue(userAgent, out int uaCount))
                {
                    if (uaCount > SUSPICIOUS_UA_THRESHOLD)
                        return true;
                }
            }

            return false;
        }

        private void StartCleanupTask()
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    var now = DateTime.UtcNow;
                    foreach (var client in clientStats)
                    {
                        if ((now - client.Value.LastRequest).TotalMinutes > 5)
                        {
                            clientStats.TryRemove(client.Key, out _);
                        }
                    }
                    tcpFloodProtection.Clear();
                    udpFloodProtection.Clear();

                    await Task.Delay(TimeSpan.FromMinutes(5));
                }
            });
        }

        public enum ProtectionType
        {
            HTTP,
            TCP,
            UDP
        }
    }
}
