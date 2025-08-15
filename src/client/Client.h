#pragma once
#include <vector>
#include <map>
#include <boost/asio.hpp>
#include "ClientEntry.h"
#include "RSAWrapper.h"
#include "AESWrapper.h"
#include "Base64Wrapper.h"

class Client
{
	// Request header structure:
    struct RequestHeader {
        char clientId[16];      // 16 bytes - unique client identifier
        uint8_t version;        // 1 byte - client version
        uint16_t code;          // 2 bytes - request code
        uint32_t payloadSize;   // 4 bytes - payload size
    };

private:
	// General information
    int _version = 1;
	std::vector<ClientEntry> _clients;

	// Client-specific information
	std::array<uint8_t, 16> _clientId; // 16 byte UUID
	std::string _clientName; // Client name, max 255 chars

	// Server connection information
	std::string _serverAddress;
	int _serverPort;

    // Socket
	bool _isConnected = false;
	std::unique_ptr<boost::asio::io_context> _ioContext;
	std::unique_ptr<boost::asio::ip::tcp::socket> _socket;

	// Encryption wrappers
	RSAPrivateWrapper _rsaPrivateWrapper;
	AESWrapper _aesWrapper;
	Base64Wrapper _base64Wrapper;

    // Request/response codes
    std::map<std::string, int> _requestCodes = {
        {"REGISTER", 600},
        {"GET_CLIENTS", 601},
        {"GET_PUBLIC_KEY", 602},
        {"SEND_MESSAGE", 603},
        {"GET_MESSAGES", 604}
    };
    std::map<std::string, int> _responseCodes = {
        {"REGISTER_SUCCESS", 2100},
        {"CLIENT_LIST", 2101},
        {"PUBLIC_KEY", 2102},
        {"MESSAGE_SENT", 2103},
        {"MESSAGES_RECEIVED", 2104},
        {"ERROR", 9000}
    };


public:
	Client();
    void run();
	void promptForInput();
    void readClientInfo();
    void readServerInfo();
	void connectToServer();
    bool ensureConnection();

	void handleClientInput(int choice);

    Client::RequestHeader buildRequestHeader(uint16_t code, uint32_t payloadSize);

	// Handlers for client actions
	void handleRegister();
	void handleGetClients();
	void handleGetPublicKey();
	void handleGetMessages();
	void handleSendMessage();
	void handleGetSymmetricKey();   
	void handleSendSymmetricKey();


	void testBoostConnection();
	void testCryptoPPConnection();
};

