using System;
using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace SimpleSecureChatServer
{
    class Program
    {
        private static ConcurrentDictionary<string, SslStream> _connectedClients = new ConcurrentDictionary<string, SslStream>();
        private static ConcurrentDictionary<string, ECDiffieHellmanPublicKey> _otherClientsPublicKeys = new ConcurrentDictionary<string, ECDiffieHellmanPublicKey>();

        static async Task Main(string[] args)
        {
            // Set server IP and port
            IPAddress serverIP = IPAddress.Parse("127.0.0.1");
            int serverPort = 5000;

            // Load the server certificate
            X509Certificate2 serverCertificate = new X509Certificate2("server.pfx", "Q4a6@8y!T7d@");

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
            {
                string clientId = null;
                ECDiffieHellmanPublicKey clientPublicKey = null;

                using (var sslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateClientCertificate), null))
                {
                    // Authenticate the server
                    await sslStream.AuthenticateAsServerAsync(serverCertificate, true, SslProtocols.Tls13, false);

                    byte[] buffer = new byte[4096];
                    int bytesRead;

                    // Register the client and store its ID
                    bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                    clientId = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    _connectedClients.TryAdd(clientId, sslStream);
                    Console.WriteLine($"Client '{clientId}' connected.");

                    // Receive the client's public key
                    bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length);
                    byte[] publicKeyBytes = new byte[bytesRead];
                    Array.Copy(buffer, publicKeyBytes, bytesRead);
                    clientPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes, CngKeyBlobFormat.EccPublicBlob);

                    _otherClientsPublicKeys[clientId] = clientPublicKey;
                    Console.WriteLine($"Client '{clientId}' has {_otherClientsPublicKeys[clientId]} public key.");

                    // Broadcast the new client's public key to all other clients
                    foreach (var otherClient in _connectedClients)
                    {
                        if (otherClient.Key != clientId)
                        {
                            byte[] publicKeyMessage = Encoding.UTF8.GetBytes($"PUBLICKEY|{clientId}|{Convert.ToBase64String(clientPublicKey.ToByteArray())}");
                            await otherClient.Value.WriteAsync(publicKeyMessage, 0, publicKeyMessage.Length);
                        }
                    }

                    // Send all the public keys of already connected clients to the new client
                    foreach (var otherClientPublicKey in _otherClientsPublicKeys)
                    {
                        if (otherClientPublicKey.Key != clientId)
                        {
                            byte[] publicKeyMessage = Encoding.UTF8.GetBytes($"PUBLICKEY|{otherClientPublicKey.Key}|{Convert.ToBase64String(otherClientPublicKey.Value.ToByteArray())}");
                            await sslStream.WriteAsync(publicKeyMessage, 0, publicKeyMessage.Length);
                        }
                    }

                    string recipientId = null;
                    byte[] messageBytes = null;

                    while ((bytesRead = await sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                    {
                        if (recipientId == null)
                        {
                            // The first message is the recipient ID
                            recipientId = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                            continue;
                        }
                        else
                        {
                            // The second message is the encrypted message content
                            messageBytes = new byte[bytesRead];
                            Array.Copy(buffer, messageBytes, bytesRead);
                        }

                        if (_connectedClients.TryGetValue(recipientId, out SslStream recipientStream))
                        {
                            await recipientStream.WriteAsync(messageBytes, 0, messageBytes.Length);
                            Console.WriteLine($"Client '{clientId}' has sent a message to recipient '{recipientId}'.");
                        }
                        else
                        {
                            Console.WriteLine($"Message routing failed. Recipient '{recipientId}' not found.");
                        }

                        // Reset for the next pair of messages
                        recipientId = null;
                        messageBytes = null;
                    }
                }

                if (clientId != null)
                {
                    _connectedClients.TryRemove(clientId, out _);
                    Console.WriteLine($"Client '{clientId}' disconnected.");

                    // Broadcast the client's disconnection to all other clients
                    foreach (var otherClient in _connectedClients)
                    {
                        byte[] disconnectMessage = Encoding.UTF8.GetBytes($"DISCONNECT|{clientId}");
                        await otherClient.Value.WriteAsync(disconnectMessage, 0, disconnectMessage.Length);
                    }
                }
            }

            static bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
            {
                // Load the CA certificate
                X509Certificate2 caCert = new X509Certificate2("cacert.pem");

                // Create a new X509 chain
                chain = new X509Chain();
                chain.ChainPolicy.ExtraStore.Add(caCert);

                // Check chain build status
                bool chainIsValid = chain.Build(new X509Certificate2(certificate));

                if (!chainIsValid)
                {
                    bool revocationStatusUnknown = false;

                    foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                    {
                        if (chainStatus.Status == X509ChainStatusFlags.RevocationStatusUnknown)
                        {
                            revocationStatusUnknown = true;
                        }
                        else
                        {
                            Console.WriteLine($"Chain error: {chainStatus.StatusInformation}");
                        }
                    }

                    // If the only error was revocationStatusUnknown, consider the chain valid
                    if (revocationStatusUnknown && chain.ChainStatus.Length == 1)
                    {
                        chainIsValid = true;
                    }
                }

                return chainIsValid;
            }

        }
    }
}
