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
	static const int CLIENT_ID_LENGTH = 16;
	static const int DEFAULT_SERVER_PORT = 1357;
	
	std::string PATH = ""; // Path to store client files

#pragma pack(push, 1) // Ensure no padding is added to the structs
    struct RequestHeader {
		std::array<uint8_t, 16> clientId;      // 16 bytes - unique client identifier
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

private:
	// Other clients
	std::vector<ClientEntry> _clients;

	// Client-specific information
	bool _isRegistered = false;
	std::array<uint8_t, 16> _clientId;
	std::string _clientName;

	// Server connection information
	std::string _serverAddress;
	int _serverPort;

    // Socket
	bool _isConnected = false;
	std::unique_ptr<boost::asio::io_context> _ioContext;
	std::unique_ptr<boost::asio::ip::tcp::socket> _socket;

	// Key pair wrapper
    std::unique_ptr<RSAPrivateWrapper> _rsaPrivateWrapper;

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

	struct IncomingMessageHeader
	{
		std::array<uint8_t, CLIENT_ID_LENGTH> senderClientId;
		uint32_t messageId;
		uint8_t messageType;
		uint32_t messageSize;
	};

	// Message types
	enum class MessageType {
		REQ_SYM_KEY = 1,
		SEND_SYM_KEY = 2,
		REGULAR = 3
	};


public:
	// Constructor and destructor
	Client();
	~Client() = default;

	// Lifecycle methods
    void run();
	void promptForInput();
	void connectToServer();
    bool ensureConnection();
	void cleanup();

	// Client information management (file I/O)
	void readClientInfo();
	void saveClientInfo();
	void readServerInfo();

	// Handlers for client actions
	void handleClientInput(int choice);
	void handleRegister();
	void handleGetClients();
	void handleGetPublicKey();
	void handleGetMessages();
	void handleSendMessage(int type);

	// Registration helper functions
	std::string getUsernameInput(const std::string& prompt);

	// Get client list helper functions
	void processClientList(const std::vector<char>& payloadBuffer);
	void displayClientList() const;

	// Get messages helper functions
	void processIncomingMessages(const std::vector<char>& payloadBuffer);
	bool parseMessageHeader(const std::vector<char>& payloadBuffer, size_t& offset, IncomingMessageHeader& messageHeader);
	std::string getSenderName(const std::array<uint8_t, CLIENT_ID_LENGTH>& senderClientId) const;
	void processMessage(const IncomingMessageHeader& messageHeader, const std::string& content, const std::string& senderName);
	void processSymmetricKeyMessage(const std::string& content, const std::array<uint8_t, CLIENT_ID_LENGTH>& senderClientId, const std::string& senderName);
	void processTextMessage(const std::string& content, const std::array<uint8_t, CLIENT_ID_LENGTH>& senderClientId);

	// Send message helper functions
	bool validateKeysForMessageType(int messageType, const ClientEntry& recipient);
	std::string prepareMessageContent(int messageType, ClientEntry& recipient);
	std::string prepareRegularMessage(const ClientEntry& recipient);
	std::string prepareSymmetricKeyMessage(ClientEntry& recipient);

	// Helper functions
    Client::RequestHeader buildRequestHeader(uint16_t code, uint32_t payloadSize);
	bool sendRequestAndReadResponse(const RequestHeader& header, const std::vector<char>& payload, ResponseHeader& responseHeader, std::vector<char>& responsePayload);
	std::array<uint8_t, 16> hexStringToBytes(const std::string& hexString) const;
	std::string bytesToHexString(const std::array<uint8_t, 16>& bytes) const;
	ClientEntry* findClientByName(const std::string& username);
	ClientEntry* findClientByUUID(const std::array<uint8_t, 16>& uuid);
};

