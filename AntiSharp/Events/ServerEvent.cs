using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace AntiSharp.Core
{
    public class ServerEvent
    {
        private readonly ConcurrentDictionary<IPAddress, ConnectionInfo> connectionTracker;
        private readonly ConcurrentDictionary<IPAddress, DateTime> blacklist;

        private const int MAX_CONNECTIONS_PER_IP = 50;
        private const int CONNECTION_TIMEOUT_SECONDS = 300;
        private const int BLACKLIST_DURATION_MINUTES = 30;
        private const int SYN_FLOOD_THRESHOLD = 100;
        private const int RATE_LIMIT_WINDOW_SECONDS = 1;
        private const int MAX_PACKETS_PER_SECOND = 500;

        public ServerEvent()
        {
            connectionTracker = new ConcurrentDictionary<IPAddress, ConnectionInfo>();
            blacklist = new ConcurrentDictionary<IPAddress, DateTime>();
            StartCleanupTask();
        }

        private class ConnectionInfo
        {
            public int ActiveConnections { get; set; }
            public DateTime LastActivity { get; set; }
            public int PacketCount { get; set; }
            public DateTime WindowStart { get; set; }
            public int SynCount { get; set; }
            public DateTime LastSynCheck { get; set; }
        }

        public bool IsAllowed(IPAddress ipAddress, bool isSynPacket = false)
        {
            if (IsBlacklisted(ipAddress))
                return false;

            var connInfo = connectionTracker.GetOrAdd(ipAddress, _ => new ConnectionInfo
            {
                WindowStart = DateTime.UtcNow,
                LastActivity = DateTime.UtcNow,
                LastSynCheck = DateTime.UtcNow
            });

            connInfo.LastActivity = DateTime.UtcNow;

            if (isSynPacket)
            {
                if ((DateTime.UtcNow - connInfo.LastSynCheck).TotalSeconds >= 1)
                {
                    connInfo.SynCount = 0;
                    connInfo.LastSynCheck = DateTime.UtcNow;
                }

                if (++connInfo.SynCount > SYN_FLOOD_THRESHOLD)
                {
                    BlacklistIP(ipAddress);
                    return false;
                }
            }

            if ((DateTime.UtcNow - connInfo.WindowStart).TotalSeconds >= RATE_LIMIT_WINDOW_SECONDS)
            {
                connInfo.PacketCount = 0;
                connInfo.WindowStart = DateTime.UtcNow;
            }

            if (++connInfo.PacketCount > MAX_PACKETS_PER_SECOND)
            {
                BlacklistIP(ipAddress);
                return false;
            }

            if (connInfo.ActiveConnections >= MAX_CONNECTIONS_PER_IP)
            {
                return false;
            }

            connInfo.ActiveConnections++;
            return true;
        }

        public void ReleaseConnection(IPAddress ipAddress)
        {
            if (connectionTracker.TryGetValue(ipAddress, out var connInfo))
            {
                if (connInfo.ActiveConnections > 0)
                    connInfo.ActiveConnections--;
            }
        }

        private bool IsBlacklisted(IPAddress ipAddress)
        {
            if (blacklist.TryGetValue(ipAddress, out DateTime blacklistTime))
            {
                if ((DateTime.UtcNow - blacklistTime).TotalMinutes < BLACKLIST_DURATION_MINUTES)
                    return true;

                blacklist.TryRemove(ipAddress, out _);
            }
            return false;
        }

        private void BlacklistIP(IPAddress ipAddress)
        {
            blacklist.TryAdd(ipAddress, DateTime.UtcNow);
        }

        private void StartCleanupTask()
        {
            Task.Run(async () =>
            {
                while (true)
                {
                    var now = DateTime.UtcNow;

                    foreach (var kvp in connectionTracker)
                    {
                        if ((now - kvp.Value.LastActivity).TotalSeconds > CONNECTION_TIMEOUT_SECONDS)
                        {
                            connectionTracker.TryRemove(kvp.Key, out _);
                        }
                    }

                    foreach (var kvp in blacklist)
                    {
                        if ((now - kvp.Value).TotalMinutes > BLACKLIST_DURATION_MINUTES)
                        {
                            blacklist.TryRemove(kvp.Key, out _);
                        }
                    }

                    await Task.Delay(TimeSpan.FromMinutes(1));
                }
            });
        }
    }
}
