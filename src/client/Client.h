#pragma once
#include <vector>
#include "ClientEntry.h"
#include <map>

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
    std::string _clientId;
    std::string _clientName;
    std::string _publicKey;
    std::string _symmetricKey;

	// Server connection information
	std::string serverAddress;
	int serverPort;

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
    void run();
	void promptForInput();
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

