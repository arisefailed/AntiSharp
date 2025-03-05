using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace AntiSharp.Logger
{
    public class ServerLogs
    {
        private readonly string logPath;
        private readonly object lockObject = new object();

        public ServerLogs(string logDirectory = "logs")
        {
            logPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, logDirectory);
            Directory.CreateDirectory(logPath);
        }

        public async Task LogAsync(string message, LogLevel level = LogLevel.Info)
        {
            string logFile = Path.Combine(logPath, $"{DateTime.Now:yyyy-MM-dd}.log");
            string logMessage = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [{level}] {message}";

            await File.AppendAllTextAsync(logFile, logMessage + Environment.NewLine);
            Console.WriteLine(logMessage);
        }

        public enum LogLevel
        {
            Info,
            Warning,
            Error,
            Security
        }
    }
}
