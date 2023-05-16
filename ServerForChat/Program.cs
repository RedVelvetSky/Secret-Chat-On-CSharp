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
        // dictionary for storing list of connected clients
        private static ConcurrentDictionary<string, SslStream> _connectedClients = new ConcurrentDictionary<string, SslStream>();

        // dictionary for storing clients public keys
        private static ConcurrentDictionary<string, ECDiffieHellmanPublicKey> _otherClientsPublicKeys = new ConcurrentDictionary<string, ECDiffieHellmanPublicKey>();
        static async Task Main (string[] args) {

            // Setting server's IP and port
            IPAddress serverIP = IPAddress.Parse("127.0.0.1");
            int serverPort = 5000;

            // Load the server certificate
            // потом добавить безопасное чтение с конфигурационного файла
            X509Certificate2 serverCertificate = new X509Certificate2("server.pfx", "Q4a6@8y!T7d@");

            Console.WriteLine("Certificates loaded correctly");

            // Create a TcpListener
            TcpListener server = new TcpListener(serverIP, serverPort);
            server.Start();

            // Console.WriteLine("");
            Console.WriteLine("Server started. Waiting for the new connections...");

            while (true)
            {
                // infinite loop to accept new clients
                TcpClient client = await server.AcceptTcpClientAsync();

                // creating task for each new client
                _ = HandleClientAsync(client, serverCertificate); 
            }
        }

        static async Task HandleClientAsync(TcpClient client, X509Certificate2 serverCertificate)
        {

            using (var SslStream = new SslStream(client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateClientCertificate), null))
            {
                // Authenticate the server
                await SslStream.AuthenticateAsServerAsync(serverCertificate, true, SslProtocols.Tls13, false);

                // to store message bytes
                byte[] buffer = new byte[4096];

                // contains number of recieved bytes
                int bytesRead;

                // Register the client and store its ID
                bytesRead = await SslStream.ReadAsync(buffer, 0, buffer.Length);

                // getting client id and store it into variable
                string clientId = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                Console.WriteLine($"\nClient id is: {clientId}.");

                // added client to a dictionary of known clients
                _connectedClients.TryAdd(clientId, SslStream);

                Console.WriteLine($"\nClient whose id is: {clientId} is connected now.");

                // read number of bytes in the public key 
                bytesRead = await SslStream.ReadAsync(buffer, 0, buffer.Length);

                // creating new array for public key
                byte[] publicKeyBytes = new byte[bytesRead];

                // copy data from buffer to created array length in bytesRead
                Array.Copy(buffer, publicKeyBytes, bytesRead);

                // setting new public key
                ECDiffieHellmanPublicKey clientPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes, CngKeyBlobFormat.EccPublicBlob);

                // adding that key to dictionary
                _otherClientsPublicKeys[clientId] = clientPublicKey;

                // Logging the public key
                byte[] publicKeyLog = clientPublicKey.ToByteArray();
                string publicKeyLogString = Convert.ToBase64String(publicKeyLog);

                // await SslStream.WriteAsync(publicKeyLog, 0, publicKeyLog.Length);

                Console.WriteLine($"\nClient {clientId} has public key: {publicKeyLogString}");

                // broadcasting accepted public key to all other's clients
                // the public key of the new client is sent to all other clients
                foreach (var otherClient in _connectedClients)
                {
                    Console.WriteLine(otherClient.Key);

                    if (otherClient.Key != clientId)
                    {
                        // creating a message, public key is written here in BASE64
                        byte[] publicKeyMessage = Encoding.UTF8.GetBytes($"PUBLICKEY|{otherClient.Key}|{publicKeyLogString}");

                        Console.WriteLine($"Sent {otherClient.Key} public key.");

                        await otherClient.Value.WriteAsync(publicKeyMessage, 0, publicKeyMessage.Length);
                    }
                }

                //  the public keys of all other clients are sent to the new client
                foreach (var otherClientPublicKey in _otherClientsPublicKeys)
                {
                    if (otherClientPublicKey.Key != clientId)
                    {   
                        // encoding public keys
                        byte[] otherPublicKeyByte = otherClientPublicKey.Value.ToByteArray();
                        string otherPublicKeyString = Convert.ToBase64String(otherPublicKeyByte);

                        byte[] publicKeyMessage = Encoding.UTF8.GetBytes($"PUBLICKEY|{otherClientPublicKey.Key}|{otherPublicKeyString}");

                        await SslStream.WriteAsync(publicKeyMessage, 0, publicKeyMessage.Length);
                    }
                }

            }
        }

        static bool ValidateClientCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors) 
        {
            return true;
        }

    }
}