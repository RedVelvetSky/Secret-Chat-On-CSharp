using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SimpleSecureChatServer
{
    class Program
    {
        private static ConcurrentDictionary<string, SslStream> _connectedClients = new ConcurrentDictionary<string, SslStream>();

        static async Task Main(string[] args)
        {
            // Set server IP and port
            IPAddress serverIP = IPAddress.Parse("127.0.0.1");
            int serverPort = 5000;

            // Load the server certificate
            X509Certificate2 serverCertificate = new X509Certificate2("server.pfx", "4-puklvife#9");

            // Create a TcpListener
            TcpListener server = new TcpListener(serverIP, serverPort);
            server.Start();

            Console.WriteLine("Server started, waiting for clients...");

            while (true)
            {
                // Accept a new client
                TcpClient client = await server.AcceptTcpClientAsync();
                _ = HandleClientAsync(client, serverCertificate); // Handle client in a separate task
            }
        }

        static async Task HandleClientAsync(TcpClient client, X509Certificate2 serverCertificate)
        {
            string clientId = null;
            using (var sslStream = new SslStream(client.GetStream(), false))
            {
                // Authenticate the server
                await sslStream.AuthenticateAsServerAsync(serverCertificate, false, SslProtocols.Tls12, false);

                byte[] buffer = new byte[4096];
                int bytesRead;

                // Register the client and store its ID
                bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                clientId = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                _connectedClients.TryAdd(clientId, sslStream);
                Console.WriteLine($"Client '{clientId}' connected.");

                while ((bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                {
                    // Process the received message
                    string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    string[] messageParts = message.Split('|');

                    if (messageParts.Length == 2)
                    {
                        string recipientId = messageParts[0];
                        string messageContent = messageParts[1];

                        if (_connectedClients.TryGetValue(recipientId, out SslStream recipientStream))
                        {
                            byte[] messageBytes = Encoding.UTF8.GetBytes($"{clientId}: {messageContent}");
                            await recipientStream.WriteAsync(messageBytes, 0, messageBytes.Length);
                            Console.WriteLine($"Client '{clientId}' has sent message '{messageContent}' to recipient '{recipientId}'.");
                        }
                        else
                        {
                            Console.WriteLine($"Message routing failed. Recipient '{recipientId}' not found.");
                        }
                    }
                    else
                    {
                        Console.WriteLine("Invalid message format received.");
                    }
                }
            }

            if (clientId != null)
            {
                _connectedClients.TryRemove(clientId, out _);
                Console.WriteLine($"Client '{clientId}' disconnected.");
            }
        }
    }
}
