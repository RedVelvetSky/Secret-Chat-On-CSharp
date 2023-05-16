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

#if false

namespace OldSecretChat
{
    public partial class MainWindow : Window
    {

        private TcpClient? _client;
        private SslStream? _sslStream;
        private ECDiffieHellmanCng ecdh;
        private Dictionary<string, ECDiffieHellmanPublicKey> _otherClientsPublicKeys = new Dictionary<string, ECDiffieHellmanPublicKey>();
        private Aes aes;

        public MainWindow()
        {
            InitializeComponent();
            ecdh = new ECDiffieHellmanCng();
            aes = Aes.Create();
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
            var clientCertificates = new X509CertificateCollection(new X509Certificate[] { clientCertificate });
            await _sslStream.AuthenticateAsClientAsync("127.0.0.1", clientCertificates, SslProtocols.Tls13, false);

            ChatTextBox.AppendText($"\n Client authenticated.");

            // Send the unique client ID to the server for registration
            byte[] clientIdBytes = Encoding.UTF8.GetBytes(ClientIdTextBox.Text);
            await _sslStream.WriteAsync(clientIdBytes, 0, clientIdBytes.Length);

            // Send the ECDH public key to the server
            byte[] publicKeyBytes = ecdh.PublicKey.ToByteArray();
            await _sslStream.WriteAsync(publicKeyBytes, 0, publicKeyBytes.Length);

            // Start listening for public keys
            _ = ListenForPublicKeysAsync();

            // Start listening for public keys and messages
            //_ = ListenForPublicKeysAndMessagesAsync();

            // Set the UI state to connected
            ConnectButton.IsEnabled = false;
            SendMessageButton.IsEnabled = true;
            DisconnectButton.IsEnabled = true;

            // Start listening for messages
            _ = ListenForMessagesAsync();
        }

        //private async Task ListenForPublicKeysAndMessagesAsync()
        //{
        //    byte[] buffer = new byte[4096];
        //    int bytesRead;

        //    while ((bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
        //    {
        //        string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);

        //        if (message.StartsWith("PUBLICKEY|"))
        //        {
        //            // This is a public key
        //            string[] parts = message.Split('|');
        //            if (parts.Length == 3)
        //            {
        //                string senderId = parts[1];
        //                string publicKeyString = parts[2];
        //                byte[] publicKeyBytes = Convert.FromBase64String(publicKeyString);
        //                ECDiffieHellmanPublicKey senderPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes, CngKeyBlobFormat.EccPublicBlob);

        //                if (!_otherClientsPublicKeys.ContainsKey(senderId))
        //                {
        //                    _otherClientsPublicKeys.Add(senderId, senderPublicKey);
        //                }
        //                else
        //                {
        //                    _otherClientsPublicKeys[senderId] = senderPublicKey;
        //                }
        //            }
        //        }
        //        else
        //        {
        //            // This is a message
        //            string senderId = message;

        //            if (_otherClientsPublicKeys.ContainsKey(senderId))
        //            {
        //                byte[] sharedSecret = ecdh.DeriveKeyMaterial(_otherClientsPublicKeys[senderId]);
        //                aes.Key = sharedSecret;

        //                using ICryptoTransform decryptor = aes.CreateDecryptor();
        //                byte[] decryptedMessage = decryptor.TransformFinalBlock(buffer, 0, bytesRead);

        //                string decryptedText = Encoding.UTF8.GetString(decryptedMessage);
        //                Dispatcher.Invoke(() => ChatTextBox.AppendText($"{decryptedText}\n"));
        //            }
        //            else
        //            {
        //                // If we don't have the sender's public key, ignore the message
        //                ChatTextBox.AppendText($"\n Ignored a message from {senderId} because we don't have their public key.");
        //            }
        //        }
        //    }
        //}

        private async Task ListenForPublicKeysAsync()
        {
            byte[] buffer = new byte[4096];
            int bytesRead;

            while ((bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
            {
                string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);

                if (message.StartsWith("PUBLICKEY|"))
                {
                    string[] parts = message.Split('|');
                    if (parts.Length == 3)
                    {

                        ChatTextBox.AppendText($"\nKey recieved!");
                        string senderId = parts[1];
                        string publicKeyString = parts[2];
                        byte[] publicKeyBytes = Convert.FromBase64String(publicKeyString);
                        ECDiffieHellmanPublicKey senderPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(publicKeyBytes, CngKeyBlobFormat.EccPublicBlob);

                        ChatTextBox.AppendText($"\nPublic key for {senderId} is {publicKeyString}.");

                        if (!_otherClientsPublicKeys.ContainsKey(senderId))
                        {
                            _otherClientsPublicKeys.Add(senderId, senderPublicKey);
                        }
                        else
                        {
                            _otherClientsPublicKeys[senderId] = senderPublicKey;
                        }
                    }
                }
            }
        }

        private async Task ListenForMessagesAsync()
        {
            byte[] buffer = new byte[4096];
            int bytesRead;
            string senderId = null;
            byte[] messageBytes = null;

            ChatTextBox.AppendText($"\n Entered the function.");

            try
            {
                while ((bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                {
                    ChatTextBox.AppendText($"\n Received a message.");

                    if (senderId == null)
                    {
                        // The first message is the sender ID
                        senderId = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                        continue;
                    }
                    else
                    {
                        // The second message is the encrypted message content
                        messageBytes = new byte[bytesRead];
                        Array.Copy(buffer, messageBytes, bytesRead);
                    }

                    if (_otherClientsPublicKeys.ContainsKey(senderId))
                    {
                        // Decrypt the message
                        byte[] sharedSecret = ecdh.DeriveKeyMaterial(_otherClientsPublicKeys[senderId]);
                        aes.Key = sharedSecret;

                        ChatTextBox.AppendText($"\n Key derived");

                        using ICryptoTransform decryptor = aes.CreateDecryptor();
                        byte[] decryptedMessage = decryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

                        string message = Encoding.UTF8.GetString(decryptedMessage);
                        Dispatcher.Invoke(() => ChatTextBox.AppendText($"{senderId}: {message}\n"));

                    }
                    else
                    {

                        ECDiffieHellmanPublicKey senderPublicKey = ECDiffieHellmanCngPublicKey.FromByteArray(buffer, CngKeyBlobFormat.EccPublicBlob);
                        ChatTextBox.AppendText($"\nAdded key: {senderPublicKey}");
                        _otherClientsPublicKeys.Add(senderId, senderPublicKey);
                    }
                }
            }
            catch (IOException ex)
            {
                ChatTextBox.AppendText($"\n Connection was closed: {ex.Message}");
                // The connection was closed
            }
        }

        private async void SendMessageButton_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(RecipientIdTextBox.Text) && !string.IsNullOrEmpty(MessageTextBox.Text))
            {
                ChatTextBox.AppendText($"\n Sending a message...");

                byte[] recipientIdBytes = Encoding.UTF8.GetBytes(RecipientIdTextBox.Text);

                // Send the recipient ID
                await _sslStream.WriteAsync(recipientIdBytes, 0, recipientIdBytes.Length);

                byte[] messageBytes = Encoding.UTF8.GetBytes(MessageTextBox.Text);

                // Encrypt the message
                byte[] sharedSecret = ecdh.DeriveKeyMaterial(_otherClientsPublicKeys[RecipientIdTextBox.Text]);
                if (!_otherClientsPublicKeys.ContainsKey(RecipientIdTextBox.Text))
                {
                    ChatTextBox.AppendText($"Error: Public key for client {RecipientIdTextBox.Text} not found.");
                    return;
                }
                aes.Key = sharedSecret;

                using ICryptoTransform encryptor = aes.CreateEncryptor();
                byte[] encryptedMessage = encryptor.TransformFinalBlock(messageBytes, 0, messageBytes.Length);

                // Prepend the length of recipientIdBytes and then the recipientIdBytes themselves
                byte[] lengthBytes = BitConverter.GetBytes(recipientIdBytes.Length);
                byte[] finalMessage = new byte[lengthBytes.Length + recipientIdBytes.Length + encryptedMessage.Length];
                Buffer.BlockCopy(lengthBytes, 0, finalMessage, 0, lengthBytes.Length);
                Buffer.BlockCopy(recipientIdBytes, 0, finalMessage, lengthBytes.Length, recipientIdBytes.Length);
                Buffer.BlockCopy(encryptedMessage, 0, finalMessage, lengthBytes.Length + recipientIdBytes.Length, encryptedMessage.Length);

                await _sslStream.WriteAsync(finalMessage, 0, finalMessage.Length);
                ChatTextBox.AppendText($"You: {MessageTextBox.Text}\n");
                MessageTextBox.Clear();
            }
        }

        private void DisconnectButton_Click(object sender, RoutedEventArgs e)
        {
            _client?.Close();
            _sslStream?.Dispose();

            ConnectButton.IsEnabled = true;
            SendMessageButton.IsEnabled = false;
            DisconnectButton.IsEnabled = false;
        }

        private static bool ValidateServerCertificate(
        object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors)
        {
            // Load the CA certificate
            X509Certificate2 caCert = new X509Certificate2("E:\\Cybersec\\Secret-Chat-On-CSharp\\SecretChat\\cacert.pem");

            // Create a new X509 chain
            chain = new X509Chain();
            chain.ChainPolicy.ExtraStore.Add(caCert);

            // Disable the revocation check
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;

            // Check chain build status
            bool chainIsValid = chain.Build(new X509Certificate2(certificate));

            if (!chainIsValid)
            {
                foreach (X509ChainStatus chainStatus in chain.ChainStatus)
                {
                    System.Windows.MessageBox.Show($"Chain error: {chainStatus.StatusInformation}");
                }
            }

            //if (sslPolicyErrors != SslPolicyErrors.None)
            //{
            //    System.Windows.MessageBox.Show($"SSL policy error: {sslPolicyErrors}");
            //    return false;
            //}
            // have had dimb issue while creating cert, if cert is created carefully there would be no errors 


            return chainIsValid;
            //return true;
        }

    }

}

#endif