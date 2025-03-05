using System;
using System.Threading.Tasks;
using AntiSharp.Server;

namespace AntiSharp
{
    class Program
    {
        static async Task Main(string[] args)
        {
            var server = new HttpServer(3000);
            await server.StartAsync();
        }
    }
}