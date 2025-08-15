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
public:
	static const int VERSION = 1;
	static const int MAX_CLIENT_NAME_LENGTH = 255;
	static const int CLIENT_ID_LENGTH = 16; // UUID length in bytes
	static const int DEFAULT_SERVER_PORT = 1357;

#pragma pack(push, 1) // Ensure no padding is added to the structs
    struct RequestHeader {
        char clientId[16];      // 16 bytes - unique client identifier
        uint8_t version;        // 1 byte - client version
        uint16_t code;          // 2 bytes - request code
        uint32_t payloadSize;   // 4 bytes - payload size
    };
	struct ResponseHeader {
		uint8_t version;        // 1 byte - server version
		uint16_t code;          // 2 bytes - response code
		uint32_t payloadSize;   // 4 bytes - payload size
	};
#pragma pack(pop)
	struct Message {
		std::string sender;
		std::string recipient;
		std::string content;
	};

private:
	// Other clients
	std::vector<ClientEntry> _clients;

	// Client-specific information
	bool _isRegistered = false;
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
    std::unique_ptr<RSAPrivateWrapper> _rsaPrivateWrapper;
	std::unique_ptr<AESWrapper> _aesWrapper;

    // Request/response codes
    std::map<std::string, uint16_t> _requestCodes = {
        {"REGISTER", 600},
        {"GET_CLIENTS", 601},
        {"GET_PUBLIC_KEY", 602},
        {"SEND_MESSAGE", 603},
        {"GET_MESSAGES", 604}
    };
    std::map<std::string, uint16_t> _responseCodes = {
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
	void saveClientInfo();
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
};

