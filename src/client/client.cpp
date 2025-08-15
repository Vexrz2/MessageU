#include "Client.h"	
#include <iostream>
#include <fstream>
#include <boost/asio.hpp>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <hex.h>
#include <osrng.h>
#include <iomanip>

using boost::asio::ip::tcp;

Client::Client()
	: _ioContext(std::make_unique<boost::asio::io_context>()), _socket(std::make_unique<tcp::socket>(*_ioContext)),
    _rsaPrivateWrapper(nullptr), _aesWrapper(nullptr)
{
	// Read Client info from my.info
    readClientInfo();

	// Read server address and port from server.info
	readServerInfo();

}

void Client::run()
{
	std::cout << "Client version: " << VERSION << std::endl;

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
	// Read client ID and name from my.info, if already registered.
    // Format:
    // Line 1: Client name
    // Line 2: UUID in ASCII representation where every two characters represent an 8-bit hex value
    // Line 3: Private key generated on first program run in base64 format
    std::ifstream clientFile(std::string("x64\\Release\\") + "my.info");
    if (!clientFile.is_open())
    {
		// User is not registered yet, create a new temp client ID and name, generate a new RSA key pair.
        _clientId = {0};
        _clientName = "";
        _rsaPrivateWrapper = std::make_unique<RSAPrivateWrapper>();
        return;
	}

	std::string line;
    for (int i = 0; i < 3 && std::getline(clientFile, line); ++i)
    {
        switch (i)
        {
        case 0:
            if (line.empty() || line.length() > MAX_CLIENT_NAME_LENGTH)
            {
                std::cerr << "Error: Client name has bad length." << std::endl;
                _clientName = "";
                return;
            }
            // Read username from file
            _clientName = line;
            break;
        case 1:
            if (line.length() != CLIENT_ID_LENGTH * 2) // Expecting 16 bytes in hex format (32 characters)
            {
                std::cerr << "Error: Invalid client ID format in my.info" << std::endl;
                _clientId = {};
                return;
            }

            // Read Client ID from file
            _clientId.fill(0);
            for (size_t j = 0; j < line.length(); j += 2)
            {
                std::string byteString = line.substr(j, 2);
                unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, CLIENT_ID_LENGTH));
                _clientId[j / 2] = byte;
            }
            break;
        case 2:
            // Read private key from file
			std::string decodedKey = Base64Wrapper::decode(line);
            _rsaPrivateWrapper = std::make_unique<RSAPrivateWrapper>(decodedKey);
            break;
        }
	}

    // If we successfully read all details, we are registered already.
    _isRegistered = true;
	std::cout << "Welcome back " << _clientName << "!" << std::endl;
}

void Client::saveClientInfo()
{
    // Save client ID and name to my.info
    std::ofstream clientFile(std::string("x64\\Release\\") + "my.info");
    if (!clientFile.is_open())
    {
        std::cerr << "Error: Could not open my.info file for writing" << std::endl;
        return;
    }
    clientFile << _clientName << std::endl;

	// Save client ID converted to hex string to my.info
    clientFile << bytesToHexString(_clientId);
    clientFile << std::endl;

    if (_rsaPrivateWrapper)
    {
        // Save private key in base64 format as single line
        std::string encodedKey = Base64Wrapper::encode(_rsaPrivateWrapper->getPrivateKey());
        encodedKey.erase(std::remove(encodedKey.begin(), encodedKey.end(), '\n'), encodedKey.end());
        encodedKey.erase(std::remove(encodedKey.begin(), encodedKey.end(), '\r'), encodedKey.end());
        clientFile << encodedKey << std::endl;
    }
    clientFile.close();
}

void Client::readServerInfo()
{
	// Read server address and port from server.info
	std::ifstream serverFile(std::string("x64\\Release\\") + "server.info");
	if (!serverFile.is_open())
	{
		// Default fallback
		std::cerr << "Error: Could not open server.info file" << std::endl;
		_serverAddress = "127.0.0.1";
		_serverPort = DEFAULT_SERVER_PORT;
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
				_serverPort = DEFAULT_SERVER_PORT;
			}
		}
		else
		{
			std::cerr << "Invalid format in server.info, expected address:port" << std::endl;
			_serverAddress = "127.0.0.1";
			_serverPort = DEFAULT_SERVER_PORT;
		}
	}
	else
	{
		std::cerr << "Error reading server.info file" << std::endl;
		_serverAddress = "127.0.0.1";
		_serverPort = DEFAULT_SERVER_PORT;
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
		std::cout << "Exiting client." << std::endl;
        cleanup();
		exit(0);
    default:
        std::cout << "Bad input." << std::endl;
	}
}

void Client::cleanup()
{
    if (_socket && _socket->is_open())
    {
        _socket->close();
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

    header.clientId = _clientId;
    header.version = static_cast<uint8_t>(VERSION);
    header.code = code;
    header.payloadSize = payloadSize;

    return header;
}

void Client::handleRegister()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    if (_isRegistered)
    {
        std::cerr << "You are already registered as " << _clientName  << std::endl;
        return;
	}

	std::string username;
	  
	// Receive username from user input
	std::cout << "Please enter desired username: ";
    std::cin.ignore(); // Clear the input buffer
    std::getline(std::cin, username);

    // Validate username length (max 254 chars to leave room for null terminator)
    if (username.empty() || username.length() > (MAX_CLIENT_NAME_LENGTH - 1))
    {
        std::cerr << "Error: Username must be between 1 and " << (MAX_CLIENT_NAME_LENGTH - 1) << " characters long." << std::endl;
        return;
    }

    // Create properly null-padded username string of exactly 255 bytes
    std::string paddedUsername(MAX_CLIENT_NAME_LENGTH, '\0');
    std::copy(username.begin(), username.end(), paddedUsername.begin());

	_clientName = paddedUsername;

	uint32_t payloadSize = MAX_CLIENT_NAME_LENGTH + RSAPublicWrapper::KEYSIZE; // Username + public key size
	Client::RequestHeader header = buildRequestHeader(_requestCodes["REGISTER"], payloadSize);

    // Create payload: username (255, null padded) + public key (160)
	std::string publicKey = _rsaPrivateWrapper->getPublicKey();
	std::string payload = paddedUsername + publicKey;

	// Construct request buffer
	std::vector<char> requestBuffer(sizeof(header) + payload.size());
	std::memcpy(requestBuffer.data(), &header, sizeof(header));
	std::memcpy(requestBuffer.data() + sizeof(header), payload.data(), payload.size());

    try
    {
        // Send request header and payload
        boost::asio::write(*_socket, boost::asio::buffer(requestBuffer));

        // Read response
		Client::ResponseHeader responseHeader;

        size_t bytesRead = boost::asio::read(*_socket, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        if (bytesRead != sizeof(responseHeader))
        {
            std::cerr << "Error reading response header from server" << std::endl;
            return;
        }
        // Check response code
        if (responseHeader.code == _responseCodes["ERROR"])
        {
            std::cerr << "Server error" << std::endl;
            return;
		}

        if (responseHeader.code == _responseCodes["REGISTER_SUCCESS"])
        {
            // Read client ID from response
			uint32_t payloadSize = responseHeader.payloadSize;
            boost::asio::read(*_socket, boost::asio::buffer(_clientId.data(), payloadSize));

            std::cout << "Registration successful!" << std::endl;
			saveClientInfo();
            _isRegistered = true;
        }
    }
    catch (std::exception& e)
    {
        std::cerr << "Error during registration: " << e.what() << std::endl;
        _isConnected = false;
        _isRegistered = false;
	}
}

void Client::handleGetClients()
{
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    if (!_isRegistered)
    {
        std::cerr << "You must register first before requesting client list." << std::endl;
        return;
	}

    RequestHeader header = buildRequestHeader(_requestCodes["GET_CLIENTS"], 0);

    try
    {
		// Send request header (no payload)
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));
        
        // Read response
        Client::ResponseHeader responseHeader;

        size_t bytesRead = boost::asio::read(*_socket, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        if (bytesRead != sizeof(responseHeader))
        {
            std::cerr << "Error reading response header from server" << std::endl;
            return;
        }
        // Check response code
        if (responseHeader.code == _responseCodes["ERROR"])
        {
            std::cerr << "Server error" << std::endl;
            return;
        }

        if (responseHeader.code == _responseCodes["CLIENT_LIST"])
        {
			// Read client list from response
            uint32_t payloadSize = responseHeader.payloadSize;
            std::vector<char> payloadBuffer(payloadSize);
            boost::asio::read(*_socket, boost::asio::buffer(payloadBuffer.data(), payloadSize));

            // Deserialize client list
            _clients.clear();
            size_t offset = 0;
            while (offset < payloadSize)
            {
                // Extract client ID (16 bytes)
				std::array<uint8_t, CLIENT_ID_LENGTH> clientId;
				std::copy(payloadBuffer.begin() + offset, payloadBuffer.begin() + offset + CLIENT_ID_LENGTH, clientId.begin());
				offset += CLIENT_ID_LENGTH;

                // Extract client name (255 bytes)
                std::string name(payloadBuffer.begin() + offset, payloadBuffer.begin() + offset + MAX_CLIENT_NAME_LENGTH);
                offset += MAX_CLIENT_NAME_LENGTH;

                ClientEntry entry(clientId, name, "", "");
                _clients.push_back(entry);
            }
            std::cout << "Received client list:" << std::endl;
            for (const auto& client : _clients)
            {
                // Convert client ID to hex string for display
				std::string clientIdHex = bytesToHexString(client.getUUID());

                std::cout << "Client ID: " << clientIdHex << ", Name: " << client.getName() << std::endl;
            }
        }
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

    if (!_isRegistered)
    {
        std::cerr << "You must register first before requesting public key." << std::endl;
        return;
    }

    std::string clientId;

    // Receive clientID from user input
    std::cout << "Please enter client ID: ";
    std::cin.ignore(); // Clear the input buffer
    std::getline(std::cin, clientId);

	// Validate client ID length (must be 16 bytes in hex format)
    if (clientId.length() != CLIENT_ID_LENGTH * 2)
    {
        std::cerr << "Error: Invalid client ID format. Must be 16 bytes in hex format." << std::endl;
        return;
	}

    RequestHeader header = buildRequestHeader(_requestCodes["GET_PUBLIC_KEY"], CLIENT_ID_LENGTH);
    
    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));

		// Convert client ID from hex string to byte array
		std::vector<char> clientIdBytes(CLIENT_ID_LENGTH);
        for (size_t i = 0; i < CLIENT_ID_LENGTH; ++i)
        {
            std::string byteString = clientId.substr(i * 2, 2);
            unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));
            clientIdBytes[i] = byte;
		}

		// Send client ID as payload
		boost::asio::write(*_socket, boost::asio::buffer(clientIdBytes.data(), clientIdBytes.size()));
        
        // Read response
        Client::ResponseHeader responseHeader;

        size_t bytesRead = boost::asio::read(*_socket, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        if (bytesRead != sizeof(responseHeader))
        {
            std::cerr << "Error reading response header from server" << std::endl;
            return;
        }
        // Check response code
        if (responseHeader.code == _responseCodes["ERROR"])
        {
            std::cerr << "Server error" << std::endl;
            return;
        }

        if (responseHeader.code == _responseCodes["PUBLIC_KEY"])
        {
            // Read public key from response
            uint32_t payloadSize = responseHeader.payloadSize;
            std::vector<char> payloadBuffer(payloadSize);
            boost::asio::read(*_socket, boost::asio::buffer(payloadBuffer.data(), payloadSize));
            // Deserialize public key
            std::string publicKey(payloadBuffer.begin(), payloadBuffer.end());

			// Store public key in the corresponding client entry
            for (auto& client : _clients)
            {
                if (client.getUUID() == (header.clientId)) // Compare with client ID
                {
                    client.setPublicKey(publicKey);
                    break;
                }
			}

			std::cout << "Successfully retrieved public key from client ID " << clientId << std::endl;
        }
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

    if (!_isRegistered)
    {
        std::cerr << "You must register first before requesting messages." << std::endl;
        return;
	}

    RequestHeader header = buildRequestHeader(_requestCodes["GET_MESSAGES"], 0);
    
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

    if (!_isRegistered)
    {
        std::cerr << "You must register first before sending messages." << std::endl;
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

    if (!_isRegistered)
    {
        std::cerr << "You must register first before requesting symmetric key." << std::endl;
        return;
    }

    RequestHeader header = buildRequestHeader(_requestCodes["GET_SYMMETRIC_KEY"], 0);
    
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

    if (!_isRegistered)
    {
        std::cerr << "You must register first before sending symmetric key." << std::endl;
        return;
	}

    const unsigned char* key = _aesWrapper->getKey();

    if (key == nullptr)
    {
        std::cerr << "Error: Symmetric key is not set." << std::endl;
        return;
    }

    // Build request header
    RequestHeader header = buildRequestHeader(_requestCodes["SEND_SYMMETRIC_KEY"], AESWrapper::DEFAULT_KEYLENGTH);

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

std::array<uint8_t, 16> Client::hexStringToBytes(const std::string& hexString) const
{
    std::array<uint8_t, 16> bytes = {};
    if (hexString.length() != 32) // 16 bytes in hex format
    {
        throw std::invalid_argument("Hex string must be 32 characters long");
    }
    for (size_t i = 0; i < 16; ++i)
    {
        std::string byteString = hexString.substr(i * 2, 2);
        bytes[i] = static_cast<uint8_t>(std::stoi(byteString, nullptr, 16));
    }
	return bytes;
}

std::string Client::bytesToHexString(const std::array<uint8_t, 16>& bytes) const
{
    std::ostringstream oss;
    for (const auto& byte : bytes)
    {
        oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    return oss.str();
}