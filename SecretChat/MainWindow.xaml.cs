using System;
using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
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

        public MainWindow()
        {
            InitializeComponent();
        }

        private async void ConnectButton_Click(object sender, RoutedEventArgs e)
        {
            string serverIP = "127.0.0.1";
            int serverPort = 5000;

            // Connect to the server
            _client = new TcpClient();
            await _client.ConnectAsync(serverIP, serverPort);

            _sslStream = new SslStream(_client.GetStream(), false, new RemoteCertificateValidationCallback(ValidateServerCertificate), null);

            // Authenticate the client
            X509Certificate2 clientCertificate = new X509Certificate2("E:\\Cybersec\\Secret-Chat-On-CSharp\\SecretChat\\server.pfx", "4-puklvife#9");
            var clientCertificates = new X509CertificateCollection(new X509Certificate[] { clientCertificate });
            await _sslStream.AuthenticateAsClientAsync("127.0.0.1", clientCertificates, SslProtocols.Tls12, false);

            // Send the unique client ID to the server for registration
            byte[] clientIdBytes = Encoding.UTF8.GetBytes(ClientIdTextBox.Text);
            await _sslStream.WriteAsync(clientIdBytes, 0, clientIdBytes.Length);

            // Set the UI state to connected
            ConnectButton.IsEnabled = false;
            SendMessageButton.IsEnabled = true;
            DisconnectButton.IsEnabled = true;

            // Start listening for messages
            _ = ListenForMessagesAsync();
        }

        private async Task ListenForMessagesAsync()
        {
            byte[] buffer = new byte[4096];
            int bytesRead;

            try
            {
                while ((bytesRead = await _sslStream.ReadAsync(buffer, 0, buffer.Length)) != 0)
                {
                    string message = Encoding.UTF8.GetString(buffer, 0, bytesRead);
                    Dispatcher.Invoke(() => ChatTextBox.AppendText($"{message}\n"));
                }
            }
            catch (IOException)
            {
                // The connection was closed
            }
        }

        private async void SendMessageButton_Click(object sender, RoutedEventArgs e)
        {
            if (!string.IsNullOrEmpty(RecipientIdTextBox.Text) && !string.IsNullOrEmpty(MessageTextBox.Text))
            {
                byte[] messageBytes = Encoding.UTF8.GetBytes($"{RecipientIdTextBox.Text}|{MessageTextBox.Text}");
                await _sslStream.WriteAsync(messageBytes, 0, messageBytes.Length);
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

        private static bool ValidateServerCertificate(object sender, X509Certificate? certificate, X509Chain? chain, SslPolicyErrors sslPolicyErrors)
        {
            // In a real application, you should validate the server certificate properly
            return true;
        }
    }

}
