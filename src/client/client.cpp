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
	: _ioContext(std::make_unique<boost::asio::io_context>()), 
	_socket(std::make_unique<tcp::socket>(*_ioContext)), _rsaPrivateWrapper(nullptr)
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

    std::ifstream clientFile(PATH + "my.info");
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
    std::ofstream clientFile(PATH + "my.info");
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
    std::ifstream serverFile(PATH + "server.info");
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
    if (!ensureConnection())
    {
        std::cerr << "Cannot perform operation: not connected to server" << std::endl;
        return;
    }

    if (!_isRegistered && choice != 110)
    {
        std::cerr << "You must register first." << std::endl;
        return;
    }

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
		handleSendMessage(static_cast<int>(Client::MessageType::REGULAR));
		break;
	case 151:
		handleSendMessage(static_cast<int>(Client::MessageType::REQ_SYM_KEY));
		break;
	case 152:
		handleSendMessage(static_cast<int>(Client::MessageType::SEND_SYM_KEY));
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

bool Client::sendRequestAndReadResponse(const RequestHeader& header, const std::vector<char>& payload,
                                        ResponseHeader& responseHeader, std::vector<char>& responsePayload)
{
    try
    {
        // Send request header
        boost::asio::write(*_socket, boost::asio::buffer(&header, sizeof(header)));

        // Send payload if not empty
        if (!payload.empty())
        {
            boost::asio::write(*_socket, boost::asio::buffer(payload));
        }

        // Read response header
        size_t bytesRead = boost::asio::read(*_socket, boost::asio::buffer(&responseHeader, sizeof(responseHeader)));
        if (bytesRead != sizeof(responseHeader))
        {
            std::cerr << "Error reading response header from server" << std::endl;
            return false;
        }

        // Check for server error
        if (responseHeader.code == _responseCodes["ERROR"])
        {
            std::cerr << "Server error" << std::endl;
            return false;
        }

        // Read response payload if present
        if (responseHeader.payloadSize > 0)
        {
            responsePayload.resize(responseHeader.payloadSize);
            boost::asio::read(*_socket, boost::asio::buffer(responsePayload.data(), responseHeader.payloadSize));
        }

        return true;
    }
    catch (std::exception& e)
    {
        _isConnected = false;
        std::cerr << "Network error: " << e.what() << std::endl;
        return false;
    }
}

void Client::handleRegister()
{
    if (_isRegistered)
    {
        std::cerr << "You are already registered as " << _clientName << std::endl;
        return;
    }

    ResponseHeader responseHeader;
    std::vector<char> responsePayload;

	std::string paddedUsername = getUsernameInput("Please enter desired username: ");

    if (paddedUsername.empty())
    {
        return;
    }

	_clientName = paddedUsername;

    // Create payload: username (255, null padded) + public key (160)	
	std::string publicKey = _rsaPrivateWrapper->getPublicKey();
	std::string payload = paddedUsername + publicKey;
	std::vector<char> payloadBuffer(payload.begin(), payload.end());
	Client::RequestHeader header = buildRequestHeader(_requestCodes["REGISTER"], payload.size());

	if (!sendRequestAndReadResponse(header, payloadBuffer, responseHeader, responsePayload))
    {
        return;
	}
    
	if (responseHeader.code == _responseCodes["REGISTER_SUCCESS"])
	{
		// Read response payload into client ID
		std::copy(responsePayload.begin(), responsePayload.begin() + CLIENT_ID_LENGTH, _clientId.begin());

		saveClientInfo();
		_isRegistered = true;

		std::cout << "Registration successful!" << std::endl;
	}
	else
	{
		std::cerr << "Unknown error. " << "Response code: " << responseHeader.code << std::endl;
	}
}

std::string Client::getUsernameInput(const std::string& prompt)
{
    std::string username;

    // Receive username from user input
    std::cout << prompt;
    std::cin.ignore(); // Clear the input buffer
    std::getline(std::cin, username);

    // Validate username length (max 254 chars to leave room for null terminator)
    if (username.empty() || username.length() > (MAX_CLIENT_NAME_LENGTH - 1))
    {
        std::cerr << "Error: Username must be between 1 and " << (MAX_CLIENT_NAME_LENGTH - 1) << " characters long." << std::endl;
        return "";
    }

    // Create properly null-padded username string of exactly 255 bytes
    std::string paddedUsername(MAX_CLIENT_NAME_LENGTH, '\0');
    std::copy(username.begin(), username.end(), paddedUsername.begin());

    return paddedUsername;
}

void Client::handleGetClients()
{
    RequestHeader header = buildRequestHeader(_requestCodes["GET_CLIENTS"], 0);
    ResponseHeader responseHeader;
    std::vector<char> responsePayload;

    if (!sendRequestAndReadResponse(header, {}, responseHeader, responsePayload))
    {
        return;
    }

    if (responseHeader.code == _responseCodes["CLIENT_LIST"])
    {
        processClientList(responsePayload);
        displayClientList();
    }
    else
    {
        std::cerr << "Unexpected response code: " << responseHeader.code << std::endl;
    }
}

void Client::processClientList(const std::vector<char>& payloadBuffer)
{
    _clients.clear();
    size_t offset = 0;
    uint32_t payloadSize = payloadBuffer.size();

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
}

void Client::displayClientList() const
{
    std::cout << "Received client list:" << std::endl;
    for (const auto& client : _clients)
    {
        // Convert client ID to hex string for display
        std::string clientIdHex = bytesToHexString(client.getUUID());

        // Remove null padding from name for display
        std::string displayName = client.getName();
        size_t nullPos = displayName.find('\0');
        if (nullPos != std::string::npos)
        {
            displayName = displayName.substr(0, nullPos);
        }

        std::cout << "Client ID: " << clientIdHex << ", Name: " << displayName << std::endl;
    }
}

void Client::handleGetPublicKey()
{
    // Receive username from user input
    std::cout << "Please enter username: ";
    std::cin.ignore(); // Clear the input buffer

    std::string username;
    std::getline(std::cin, username);

    if (username.empty())
    {
        std::cerr << "Error: Input cannot be empty." << std::endl;
        return;
    }

    // Find the client by username
    ClientEntry* targetClient = findClientByName(username);
    if (!targetClient)
    {
        std::cerr << "Error: Client '" << username << "' not found in client list." << std::endl;
        std::cerr << "Please request the client list first (option 120)." << std::endl;
        return;
    }

    // Get client ID
    std::array<uint8_t, CLIENT_ID_LENGTH> clientId = targetClient->getUUID();
    std::vector<char> clientIdBytes(clientId.begin(), clientId.end());

    RequestHeader header = buildRequestHeader(_requestCodes["GET_PUBLIC_KEY"], CLIENT_ID_LENGTH);
    ResponseHeader responseHeader;
    std::vector<char> responsePayload;

    if (!sendRequestAndReadResponse(header, clientIdBytes, responseHeader, responsePayload))
    {
        return;
    }

	// Read response
    if (responseHeader.code == _responseCodes["PUBLIC_KEY"])
    {
        // Extract client ID (16 bytes)
        std::array<uint8_t, CLIENT_ID_LENGTH> receivedClientId;
        std::copy(responsePayload.begin(), responsePayload.begin() + CLIENT_ID_LENGTH, receivedClientId.begin());

        // Extract public key (160 bytes)
        std::string publicKey(responsePayload.begin() + CLIENT_ID_LENGTH,
            responsePayload.begin() + CLIENT_ID_LENGTH + RSAPublicWrapper::KEYSIZE);

        // Find the client and store the public key
        ClientEntry* client = findClientByUUID(receivedClientId);
        client->setPublicKey(publicKey);

        std::cout << "Successfully retrieved public key for user '" << username << "'" << std::endl;
    }
    else
    {
        std::cerr << "Unexpected response code: " << responseHeader.code << std::endl;
    }
}

void Client::handleGetMessages()
{
	// Build request header for getting messages (empty payload)
    RequestHeader header = buildRequestHeader(_requestCodes["GET_MESSAGES"], 0);
    ResponseHeader responseHeader;
    std::vector<char> responsePayload;

    if (!sendRequestAndReadResponse(header, {}, responseHeader, responsePayload))
    {
        return;
    }

    if (responseHeader.code == _responseCodes["MESSAGES_RECEIVED"])
    {
        if (responsePayload.empty())
        {
            std::cout << "No pending messages." << std::endl;
            return;
        }

        processIncomingMessages(responsePayload);
    }
    else
    {
        std::cerr << "Unexpected response code: " << responseHeader.code << std::endl;
    }
}

void Client::processIncomingMessages(const std::vector<char>& payloadBuffer)
{
    size_t offset = 0;
    uint32_t payloadSize = payloadBuffer.size();

    while (offset < payloadSize)
    {
		// Parse message header
        IncomingMessageHeader messageHeader;
        if (!parseMessageHeader(payloadBuffer, offset, messageHeader))
        {
            std::cerr << "Error parsing message header" << std::endl;
            break;
        }

        // Extract message content
        std::string content(payloadBuffer.begin() + offset,
            payloadBuffer.begin() + offset + messageHeader.messageSize);
        offset += messageHeader.messageSize;

        std::string senderName = getSenderName(messageHeader.senderClientId);

        processMessage(messageHeader, content, senderName);
		std::cout << "-----<EOM>-----" << std::endl; // Generic EOM marker
    }
}

bool Client::parseMessageHeader(const std::vector<char>& payloadBuffer, size_t& offset, IncomingMessageHeader& messageHeader)
{
    const size_t headerSize = CLIENT_ID_LENGTH + sizeof(uint32_t) + sizeof(uint8_t) + sizeof(uint32_t);

    if (offset + headerSize > payloadBuffer.size())
    {
        return false;
    }

    // Extract Client ID (16 bytes)
    std::copy(payloadBuffer.begin() + offset,
        payloadBuffer.begin() + offset + CLIENT_ID_LENGTH,
        messageHeader.senderClientId.begin());
    offset += CLIENT_ID_LENGTH;

    // Extract Message ID (4 bytes)
    std::memcpy(&messageHeader.messageId, payloadBuffer.data() + offset, sizeof(messageHeader.messageId));
    offset += sizeof(messageHeader.messageId);

    // Extract Message Type (1 byte)
    std::memcpy(&messageHeader.messageType, payloadBuffer.data() + offset, sizeof(messageHeader.messageType));
    offset += sizeof(messageHeader.messageType);

    // Extract Message Size (4 bytes)
    std::memcpy(&messageHeader.messageSize, payloadBuffer.data() + offset, sizeof(messageHeader.messageSize));
    offset += sizeof(messageHeader.messageSize);

    return true;
}

std::string Client::getSenderName(const std::array<uint8_t, CLIENT_ID_LENGTH>& senderClientId) const
{
    for (const auto& client : _clients)
    {
        if (client.getUUID() == senderClientId)
        {
            std::string name = client.getName();
            size_t nullPos = name.find('\0');
            if (nullPos != std::string::npos)
            {
                name = name.substr(0, nullPos);
            }
            return name;
        }
    }
    return "Unknown";
}

void Client::processMessage(const IncomingMessageHeader& messageHeader, const std::string& content, const std::string& senderName)
{
    std::cout << "From: " << senderName << std::endl;
    std::cout << "Content: ";

    switch (messageHeader.messageType)
    {
    case static_cast<int>(Client::MessageType::REQ_SYM_KEY):
        std::cout << "Request for symmetric key" << std::endl;
        break;

	case static_cast<int>(Client::MessageType::SEND_SYM_KEY):
        std::cout << std::endl;
        processSymmetricKeyMessage(content, messageHeader.senderClientId, senderName);
        break;

	case static_cast<int>(Client::MessageType::REGULAR):
        std::cout << std::endl;
        processTextMessage(content, messageHeader.senderClientId);
        break;

    default:
        std::cout << "Unknown message type (" << static_cast<int>(messageHeader.messageType) << ")" << std::endl;
        break;
    }
}

void Client::processSymmetricKeyMessage(const std::string& content, const std::array<uint8_t, CLIENT_ID_LENGTH>& senderClientId, const std::string& senderName)
{
    try
    {
        std::string decryptedKey = _rsaPrivateWrapper->decrypt(content);

        // Find the client and store the symmetric key
		ClientEntry* client = findClientByUUID(senderClientId);
		client->setSymmetricKey(decryptedKey);
		std::cout << "Received symmetric key from " << senderName << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error decrypting symmetric key: " << e.what() << std::endl;
    }
}

void Client::processTextMessage(const std::string& content, const std::array<uint8_t, CLIENT_ID_LENGTH>& senderClientId)
{
    // Find the symmetric key for this sender
    ClientEntry* client = findClientByUUID(senderClientId);
    if (!client || client->getSymmetricKey().empty())
    {
        std::cout << "Can't decrypt message" << std::endl;
        return;
    }

    try
    {
        const std::string& symmetricKey = client->getSymmetricKey();
        AESWrapper aesWrapper(reinterpret_cast<const unsigned char*>(symmetricKey.c_str()),
            symmetricKey.length());
        std::string decryptedMessage = aesWrapper.decrypt(content.c_str(), content.length());
        std::cout << decryptedMessage << std::endl;
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error decrypting message: " << e.what() << std::endl;
    }
}

void Client::handleSendMessage(int type)
{
    // Get recipient from user input
    std::string recipient;
    std::cout << "Enter recipient username: ";
    std::cin >> recipient;

	// Validate recipient name length
    if (recipient.empty() || recipient.length() > MAX_CLIENT_NAME_LENGTH)
    {
        std::cerr << "Error: Recipient name must be between 1 and " << MAX_CLIENT_NAME_LENGTH << " characters long." << std::endl;
        return;
    }
    
	// Get existing recipient client ID, public key, and symmetric key
    ClientEntry* recipientClient = findClientByName(recipient);
    if (!recipientClient)
    {
        std::cerr << "Error: Recipient '" << recipient << "' not found." << std::endl;
        std::cerr << "Please request the client list first (option 120)." << std::endl;
        return;
    }

    // Validate required keys for message type
    if (!validateKeysForMessageType(type, *recipientClient))
    {
        return;
    }

	// Prepare and encrypt message content based on type
    std::string encryptedMessage = prepareMessageContent(type, *recipientClient);
    std::cout << type << std::endl;
    if (encryptedMessage.empty() && type != static_cast<int>(MessageType::REQ_SYM_KEY))
    {
        return; // Error already printed in prepareMessageContent
    }

	// Build payload: Client ID (16 bytes)  + Message Type (1 byte) + Message Size (4 bytes) + Encrypted Message
	uint32_t payloadSize = CLIENT_ID_LENGTH + sizeof(uint8_t) + sizeof(uint32_t) + encryptedMessage.size();
	std::vector<char> payloadBuffer(payloadSize);
	size_t offset = 0;

	// Copy recipient Client ID
	std::array<uint8_t, CLIENT_ID_LENGTH> recipientId = recipientClient->getUUID();
	std::copy(recipientId.begin(), recipientId.end(), payloadBuffer.data() + offset);
	offset += CLIENT_ID_LENGTH;

	// Copy message type
	uint8_t messageType = static_cast<uint8_t>(type);
	std::memcpy(payloadBuffer.data() + offset, &messageType, sizeof(messageType));
	offset += sizeof(messageType);

	// Copy message size
	uint32_t messageSize = static_cast<uint32_t>(encryptedMessage.size());
	std::memcpy(payloadBuffer.data() + offset, &messageSize, sizeof(messageSize));
	offset += sizeof(messageSize);

	// Copy encrypted message
	std::memcpy(payloadBuffer.data() + offset, encryptedMessage.data(), encryptedMessage.size());

    // Build request header
    RequestHeader header = buildRequestHeader(_requestCodes["SEND_MESSAGE"], payloadSize);

	// Prepare response header and payload
    ResponseHeader responseHeader;
    std::vector<char> responsePayload;

    if (!sendRequestAndReadResponse(header, payloadBuffer, responseHeader, responsePayload))
    {
        return;
    }

    if (responseHeader.code == _responseCodes["MESSAGE_SENT"])
    {
		// We can do something with the response payload if needed, but it's not used. (Client ID + Message ID)

        std::cout << "Message sent successfully." << std::endl;
    }
    else
    {
        std::cerr << "Unexpected response code: " << responseHeader.code << std::endl;
    }
}

bool Client::validateKeysForMessageType(int messageType, const ClientEntry& recipient)
{
    switch (messageType)
    {
    case static_cast<int>(MessageType::REGULAR):
        if (recipient.getSymmetricKey().empty())
        {
            std::cerr << "Error: Symmetric key for recipient not found." << std::endl;
            std::cerr << "Please exchange symmetric keys first (option 151/152)." << std::endl;
            return false;
        }
        break;

    case static_cast<int>(MessageType::REQ_SYM_KEY):
        // No keys needed for requesting symmetric key
		break;

    case static_cast<int>(MessageType::SEND_SYM_KEY):
        if (recipient.getPublicKey().empty())
        {
            std::cerr << "Error: Public key for recipient not found." << std::endl;
            std::cerr << "Please request the public key first (option 130)." << std::endl;
            return false;
        }
        break;
    default:
        std::cerr << "Error: Unknown message type." << std::endl;
        return false;
    }

    return true;
}

std::string Client::prepareMessageContent(int messageType, ClientEntry& recipient)
{
    switch (messageType)
    {
    case static_cast<int>(MessageType::REGULAR):
        return prepareRegularMessage(recipient);

    case static_cast<int>(MessageType::REQ_SYM_KEY):
        return ""; // Empty message for symmetric key request

    case static_cast<int>(MessageType::SEND_SYM_KEY):
        return prepareSymmetricKeyMessage(recipient);

    default:
        std::cerr << "Error: Unknown message type." << std::endl;
        return "";
    }
}

std::string Client::prepareRegularMessage(const ClientEntry& recipient)
{
    std::cout << "Enter message content: ";

    std::string message;
	std::cin.ignore(); // Clear the input buffer
    std::getline(std::cin, message);

    if (message.empty())
    {
        std::cerr << "Error: Message content cannot be empty." << std::endl;
        return "";
    }

    // Encrypt message using AES symmetric key
    try
    {
        const std::string& symmetricKey = recipient.getSymmetricKey();
        AESWrapper aesWrapper(reinterpret_cast<const unsigned char*>(symmetricKey.c_str()),
            symmetricKey.length());
        return aesWrapper.encrypt(message.c_str(), message.length());
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: Failed to encrypt message: " << e.what() << std::endl;
        return "";
    }
}

std::string Client::prepareSymmetricKeyMessage(ClientEntry& recipient)
{
    // Generate a random symmetric key
    AESWrapper aesWrapper;
    const unsigned char* symmetricKey = aesWrapper.getKey();
    std::string symmetricKeyStr(reinterpret_cast<const char*>(symmetricKey),
        AESWrapper::DEFAULT_KEYLENGTH);

    // Store the symmetric key for this recipient
    recipient.setSymmetricKey(symmetricKeyStr);

    // Encrypt symmetric key using recipient's public key
    try
    {
        RSAPublicWrapper rsaPublicWrapper(recipient.getPublicKey());
        return rsaPublicWrapper.encrypt(symmetricKeyStr);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: Failed to encrypt symmetric key: " << e.what() << std::endl;
        return "";
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

ClientEntry* Client::findClientByName(const std::string& username)
{
    for (auto& client : _clients)
    {
        // Remove null padding from client name before comparison
        std::string clientName = client.getName();
        size_t nullPos = clientName.find('\0');
        if (nullPos != std::string::npos)
        {
            clientName = clientName.substr(0, nullPos);
        }

        if (clientName == username)
        {
            return &client;
        }
    }
    return nullptr;
}

ClientEntry* Client::findClientByUUID(const std::array<uint8_t, CLIENT_ID_LENGTH>& uuid)
{
    for (auto& client : _clients)
    {
        if (client.getUUID() == uuid)
        {
            return &client;
        }
    }
    return nullptr;
}