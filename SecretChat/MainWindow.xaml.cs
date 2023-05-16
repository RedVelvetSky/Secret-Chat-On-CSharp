using System;
using System.Collections.Generic;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;
using System.Windows;

namespace SecretChat
{
    public partial class MainWindow : Window
    {
        private TcpClient? _client;
        private SslStream? _sslStream;
        private ECDiffieHellmanCng ECDH;
        private Dictionary<string, ECDiffieHellmanPublicKey> _otherClientsPublicKeys = new Dictionary<string, ECDiffieHellmanPublicKey>();

        public MainWindow()
        {
            InitializeComponent();
            ECDH = new ECDiffieHellmanCng();
        }

        private async void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            string serverIP = "127.0.0.1";
            int serverPort = 5000;

            //ChatTextBox.AppendText($"\n");
            ChatTextBox.AppendText($"\n Connecting to the server...");

            // Connect to the server
            _client = new TcpClient();
            await _client.ConnectAsync(serverIP, serverPort);

            ChatTextBox.AppendText($"\n Connected to the server.");

            _sslStream = new SslStream(_client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            ChatTextBox.AppendText($"\n Authenticating the client...");

            // Authenticate the client
            X509Certificate2 clientCertificate = new X509Certificate2("E:\\Cybersec\\Secret-Chat-On-CSharp\\SecretChat\\client.pfx", "I!vW70n1xnoH");

            //Creating instance of certificate
            var clientCertificates = new X509CertificateCollection(new X509Certificate[] { clientCertificate });

            //Sending certificate
            await _sslStream.AuthenticateAsClientAsync("127.0.0.1", clientCertificates, SslProtocols.Tls13, false);

            ChatTextBox.AppendText($"\n Client authenticated.");

            // Sending the unique client ID to the server for registration
            byte[] clientIdBytes = Encoding.UTF8.GetBytes(ClientIdTextBox.Text);

            await _sslStream.WriteAsync(clientIdBytes, 0, clientIdBytes.Length);

            //generating public key
            byte[] publicKeyBytes = ECDH.PublicKey.ToByteArray();

            //sending public key to server
            await _sslStream.WriteAsync(publicKeyBytes, 0, publicKeyBytes.Length);

            ChatTextBox.AppendText($"\n Public key has sent.");

            //await _sslStream.ReadAsync(publicKeyBytes, 0, publicKeyBytes.Length);

            // Set the UI state to connected
            ConnectButton.IsEnabled = false;
            SendMessageButton.IsEnabled = true;
            DisconnectButton.IsEnabled = true;

            // Start listening for messages
            _ = ListenForMessagesAsync();
        }

        private async Task ListenForMessagesAsync()
        {
            ChatTextBox.AppendText($"\n Entered the ListenForMessagesAsync() function.");
            var buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
            {
                ChatTextBox.AppendText($"\n Having some data.");
                //var byteCount = await _sslStream.ReadAsync(buffer, 0, buffer.Length);
                var message = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                // check if the message is a public key
                if (message.StartsWith("PUBLICKEY|"))
                {
                    ChatTextBox.AppendText($"\n Received public key.");
                    //handling public key incoming

                    // extract client id and public key from the message
                    var parts = message.Split('|');
                    var otherClientId = parts[1];
                    var publicKeyString = parts[2];

                    // convert the base64 string back to a byte array
                    var publicKeyBytes = Convert.FromBase64String(publicKeyString);

                    // recreate the public key from byte array
                    ECDiffieHellmanPublicKey senderPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes, CngKeyBlobFormat.EccPublicBlob);

                    if (!_otherClientsPublicKeys.ContainsKey(otherClientId))
                    {
                        //adding new public key to dictionary
                        _otherClientsPublicKeys.Add(otherClientId, senderPublicKey);

                        //debugging message with public key in BASE64 and id
                        ChatTextBox.AppendText($"\n Added public key: {publicKeyString} for {otherClientId}");
                    }
                    else
                    {
                        //renew public key
                        _otherClientsPublicKeys[otherClientId] = senderPublicKey;
                    }
                }
                else
                {
                    // handling normal message
                }
            }
        }


        private async void SendMessageButton_Click(object sender, RoutedEventArgs e)
        {
            
        }

        private void DisconnectButton_Click(object sender, RoutedEventArgs e)
        {
            Close();
        }

        private static bool ValidateServerCertificate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
        { return true; }
    }
}