#pragma once
#include <vector>
#include "ClientEntry.h"

class Client
{
private:
    std::size_t _version = 1;
	std::vector<ClientEntry> _clients;
    std::string _clientId;
    std::string _clientName;
    std::string _publicKey;
    std::string _symmetricKey;
	std::string serverAddress;
	std::size_t serverPort;

public:
    void run();
	void promptForInput();

    void initializeClient();
    void connectToServer();
    void handleIncomingMessages();
    void sendMessage(const std::string& message);
    void receiveMessage();


};

