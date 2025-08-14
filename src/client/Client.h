#pragma once
#include <vector>
#include "ClientEntry.h"

class Client
{
private:
    int _version = 1;
	std::vector<ClientEntry> _clients;
    std::string _clientId;
    std::string _clientName;
    std::string _publicKey;
    std::string _symmetricKey;
	std::string serverAddress;
	int serverPort;

public:
    void run();
	void promptForInput();
	void handle_client_input(int choice);
	void testBoostConnection();
	void testCryptoPPConnection();
};

