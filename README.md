# Secret-Chat-On-CSharp
## Introduction

Secret Chat is a simple client-server chat application that provides end-to-end encryption using SSL/TLS. The client and server are written in C# using the .NET Framework, and use the SslStream class to establish a secure connection over TCP/IP. The application allows users to exchange messages securely between two or more clients, using a unique client ID to identify each client.
Requirements

To run the Secret Chat application, you need the following:

    .NET Framework 4.7.2 or later installed on your computer.
    Visual Studio 2019 or later to build and run the project.

## Installation

To install and run the Secret Chat application:

    1. Clone or download the project files from the GitHub repository.
    2. Open the project in Visual Studio.
    3. Build the project to compile the executable files.
    4. Run the server application (SimpleSecureChatServer.exe) on a computer that will act as the chat server.
    5. Run the client application (SecretChat.exe) on one or more client computers that will connect to the server.
    6. Enter a unique client ID for each client in the "Your ID" field.
    7. Enter the IP address or hostname of the server in the "Recipient ID" field.
    8. Click the "Connect" button to establish a secure connection with the server.
    9. Type a message in the message box and click the "Send" button to send a message to the recipient.

## Usage

The Secret Chat application provides a simple user interface that allows users to exchange secure messages with other clients. Here are the basic steps to use the application:

    1. Run the server application on a computer that will act as the chat server.
    2. Run the client application on one or more client computers that will connect to the server.
    3. Enter a unique client ID for each client in the "Your ID" field.
    4. Enter the IP address or hostname of the server in the "Recipient ID" field.
    5. Click the "Connect" button to establish a secure connection with the server.
    6. Type a message in the message box and click the "Send" button to send a message to the recipient.

The application allows you to send messages to one or more recipients by entering their client ID in the "Recipient ID" field. You can also disconnect from the server by clicking the "Disconnect" button.

## Security

The Secret Chat application uses **SSL/TLS** to establish a secure connection between the client and server. The client and server use **X.509** certificates to authenticate each other and to encrypt the communication channel using public key cryptography.

The application uses the SslStream class to wrap the **TCP/IP** stream with **SSL/TLS** encryption. The SslStream class uses the .NET Framework cryptography libraries to implement the **SSL/TLS** protocol and the **X.509** certificate validation and authentication.

## Disclaimer

The Secret Chat application is **provided as-is**, without any warranty or guarantee of security or accuracy. The application is intended for educational or demonstration purposes only, and should not be used for sensitive or confidential communication. The application may contain bugs or vulnerabilities that could be exploited by attackers. Use at your own risk.
