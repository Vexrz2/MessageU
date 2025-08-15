#include "Client.h"	
#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <hex.h>
#include <osrng.h>

using boost::asio::ip::tcp;

Client::Client()
	: _rsaPrivateWrapper(), _aesWrapper(), _base64Wrapper(), _ioContext(std::make_unique<boost::asio::io_context>()), 
      _socket(std::make_unique<tcp::socket>(*_ioContext))
{
	// Read Client info from my.info
    readClientInfo();

	// Read server address and port from server.info
	readServerInfo();

}

void Client::run()
{
	std::cout << "Client version: " << _version << std::endl;

	try 
    {
        connectToServer();
    } 
    catch (const std::exception& e) 
    {
        std::cerr << "Error connecting to server." << std::endl;
        return;
	}

	while (true)
	{
		promptForInput();
		int choice;
		std::cin >> choice;

		handleClientInput(choice);
	}
}

void Client::readClientInfo()
{
	// Read client ID and name from my.info, if already registered
    // Format:
    // Line 1: Client name
    // Line 2: UUID in ASCII representation where every two characters represent an 8-bit hex value
    // Line 3: Private key generated on first program run in base64 format
	std::ifstream clientFile("my.info");

    if (!clientFile.is_open())
    {
        std::cerr << "Error: Could not open my.info file" << std::endl;
        _clientId = {};
        _clientName = "";
        return;
	}

	std::string line;
    for (int i = 0; i < 3 && std::getline(clientFile, line); ++i)
    {
        switch (i)
        {
        case 0:
            if (line.empty() || line.length() >= 255)
            {
				std::cerr << "Error: Client name has bad length." << std::endl;
				_clientName = "";
				return;
            }
            _clientName = line; // Client name
            break;
        case 1:
            if (line.length() != 32) // Expecting 16 bytes in hex format (32 characters)
            {
                std::cerr << "Error: Invalid client ID format in my.info" << std::endl;
                _clientId = {};
                return;
			}
			_clientId.fill(0); // Initialize to zero
			// Convert hex string to byte array
            for (size_t j = 0; j < line.length(); j += 2)
            {
                std::string byteString = line.substr(j, 2);
                unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
                _clientId[j / 2] = byte;
			}
            break;
        case 2:
            std::string decodedKey = Base64Wrapper::decode(line);
			_rsaPrivateWrapper = RSAPrivateWrapper(reinterpret_cast<const unsigned char*>(decodedKey.c_str()));
            break;
        }
	}
}

void Client::readServerInfo()
{
	// Read server address and port from server.info
	std::ifstream serverFile("server.info");
	if (!serverFile.is_open())
	{
		// Default fallback
		std::cerr << "Error: Could not open server.info file" << std::endl;
		_serverAddress = "127.0.0.1";
		_serverPort = 1357;            
		return;
	}

	std::string line;
	if (std::getline(serverFile, line))
	{
		size_t colonPos = line.find(':');
		if (colonPos != std::string::npos)
		{
			_serverAddress = line.substr(0, colonPos);
			try
			{
				_serverPort = std::stoi(line.substr(colonPos + 1));
			}
			catch (const std::exception& e)
			{
				std::cerr << "Error parsing port number, using default 1357" << std::endl;
				_serverPort = 1357;
			}
		}
		else
		{
			std::cerr << "Invalid format in server.info, expected address:port" << std::endl;
			_serverAddress = "127.0.0.1";
			_serverPort = 1357;
		}
	}
	else
	{
		std::cerr << "Error reading server.info file" << std::endl;
		_serverAddress = "127.0.0.1";
		_serverPort = 1357;
	}

	serverFile.close();}

void Client::connectToServer()
{
	if (_isConnected && _socket->is_open())
	{
		std::cout << "Already connected to server" << std::endl;
		return;
	}

	tcp::resolver resolver(*_ioContext);
	tcp::resolver::results_type endpoints = resolver.resolve(_serverAddress, std::to_string(_serverPort));

	// Close existing socket if open
	if (_socket->is_open())
	{
		_socket->close();
	}

	boost::asio::connect(*_socket, endpoints);
	_isConnected = true;

	std::cout << "Connected to server at " << _serverAddress << ":" << _serverPort << std::endl;
}

bool Client::ensureConnection()
{
	if (!_isConnected || !_socket->is_open())
	{
		std::cout << "Attempting to reconnect to server..." << std::endl;
		connectToServer();
    }
    return _isConnected;
}

void Client::promptForInput()
{
	std::cout << "MessageU client at your service." << std::endl;
	std::cout << "110) Register" << std::endl;
	std::cout << "120) Request for clients list" << std::endl;
	std::cout << "130) Request for public key" << std::endl;
	std::cout << "140) Request for waiting messages" << std::endl;
	std::cout << "150) Send a text message" << std::endl;
	std::cout << "151) Send a request for symmetric key" << std::endl;
	std::cout << "152) Send your symmetric key" << std::endl;
	std::cout << "0) Exit client" << std::endl;
	std::cout << "? ";
}

void Client::handleClientInput(int choice)
{
	switch (choice)
	{
	case 110:
		handleRegister();
		break;
	case 120:
		handleGetClients();
		break;
	case 130:
		handleGetPublicKey();
		break;
	case 140:
		handleGetMessages();
		break;
	case 150:
		handleSendMessage();
		break;
	case 151:
		handleGetSymmetricKey();
		break;
	case 152:
		handleSendSymmetricKey();
		break;
	case 0:
	default:
		std::cout << "Exiting client." << std::endl;
		exit(0);
	}
}

Client::RequestHeader Client::buildRequestHeader(uint16_t code, uint32_t payloadSize)
{
    // Request header structure:
    // Client ID: 16 bytes (128 bit unique identifier)
    // Version: 1 byte
    // Code: 2 bytes (request code)
    // Payload size: 4 bytes (content size)
    
    RequestHeader header;
    
    // Initialize client ID (pad with zeros if shorter than 16 bytes)
    memset(header.clientId, 0, 16);
    if (!_clientId.empty()) {
        size_t copySize = std::min(_clientId.length(), static_cast<size_t>(16));
        memcpy(header.clientId, _clientId.c_str(), copySize);
    }
    
    // Set version
    header.version = static_cast<uint8_t>(_version);
    
    // Code and payload size will be set by specific request handlers
    header.code = 0;
    header.payloadSize = 0;
    
	return header;
}

void Client::handleRegister()
{
	std::string username;
	  
	// Receive username from user input
	std::cout << "Please enter desired username: ";
	std::cin >> username;


}

void Client::handleGetClients()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    RequestHeader header = buildRequestHeader(_requestCodes["GET_CLIENTS"], 0);
    header.code = _requestCodes["GET_CLIENTS"];
    header.payloadSize = 0;

    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Read response
        char response[1024];
        size_t len = _socket->read_some(boost::asio::buffer(response));
        
        std::cout << "Received response: " << std::string(response, len) << std::endl;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Error getting clients: " << e.what() << std::endl;
    }
}

void Client::handleGetPublicKey()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    RequestHeader header = buildRequestHeader(_requestCodes["GET_PUBLIC_KEY"], 0);
    header.code = _requestCodes["GET_PUBLIC_KEY"];
    header.payloadSize = 0;
    
    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Read response
        char response[1024];
        size_t len = _socket->read_some(boost::asio::buffer(response));
        
        std::cout << "Received public key: " << std::string(response, len) << std::endl;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Error getting public key: " << e.what() << std::endl;
    }
}

void Client::handleGetMessages()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    RequestHeader header = buildRequestHeader(_requestCodes["GET_MESSAGES"], 0);
    header.code = _requestCodes["GET_MESSAGES"];
    header.payloadSize = 0;
    
    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Read response
        char response[1024];
        size_t len = _socket->read_some(boost::asio::buffer(response));
        
        std::cout << "Received messages: " << std::string(response, len) << std::endl;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Error getting messages: " << e.what() << std::endl;
    }
}

void Client::handleSendMessage()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    // Get recipient and message from user input
    std::string recipient, message;
    std::cout << "Enter recipient username: ";
    std::cin >> recipient;
    std::cout << "Enter your message: ";
    std::cin.ignore(); // Clear newline character from previous input
    std::getline(std::cin, message);
    
    // Encrypt the message using AES
    AESWrapper aesWrapper;
    std::string encryptedMessage = aesWrapper.encrypt(message.c_str(), message.length());
    
    // Build request header
    RequestHeader header = buildRequestHeader(_requestCodes["SEND_MESSAGE"], encryptedMessage.size());
    header.code = _requestCodes["SEND_MESSAGE"];
    header.payloadSize = encryptedMessage.size();
    
    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Send encrypted message
        boost::asio::write(*_socket, boost::asio::buffer(encryptedMessage));
        
        std::cout << "Message sent successfully." << std::endl;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Error sending message: " << e.what() << std::endl;
    }
}

void Client::handleGetSymmetricKey()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    RequestHeader header = buildRequestHeader(_requestCodes["GET_SYMMETRIC_KEY"], 0);
    header.code = _requestCodes["GET_SYMMETRIC_KEY"];
    header.payloadSize = 0;
    
    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Read response
        char response[1024];
        size_t len = _socket->read_some(boost::asio::buffer(response));
        
        std::cout << "Received symmetric key: " << std::string(response, len) << std::endl;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Error getting symmetric key: " << e.what() << std::endl;
    }
}

void Client::handleSendSymmetricKey()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    const unsigned char* key = _aesWrapper.getKey();

    if (key == nullptr)
    {
        std::cerr << "Error: Symmetric key is not set." << std::endl;
        return;
    }

    // Build request header
    RequestHeader header = buildRequestHeader(_requestCodes["SEND_SYMMETRIC_KEY"], AESWrapper::DEFAULT_KEYLENGTH);
    header.code = _requestCodes["SEND_SYMMETRIC_KEY"];
    header.payloadSize = AESWrapper::DEFAULT_KEYLENGTH;

    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Send symmetric key
        boost::asio::write(*_socket, boost::asio::buffer(key, AESWrapper::DEFAULT_KEYLENGTH));
        
        std::cout << "Symmetric key sent successfully." << std::endl;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Error sending symmetric key: " << e.what() << std::endl;
    }
}