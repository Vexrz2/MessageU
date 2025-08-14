#include "Client.h"	
#include <iostream>
#include <boost/asio.hpp>
#include <aes.h>
#include <modes.h>
#include <filters.h>
#include <hex.h>
#include <osrng.h>

using boost::asio::ip::tcp;

void Client::run()
{
	std::cout << "Client version: " << _version << std::endl;
	
	// Temp test connections
	testBoostConnection();
	testCryptoPPConnection();
	
	while (true)
	{
		promptForInput();
		int choice;
		std::cin >> choice;

		handleClientInput(choice);
	}
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

void Client::testBoostConnection()
{
	try 
	{
		boost::asio::io_context io_context;
		tcp::socket socket(io_context);
		tcp::resolver resolver(io_context);
		
		std::cout << "Testing boost connection to localhost:8888..." << std::endl;
		
		auto endpoints = resolver.resolve("127.0.0.1", "8888");
		boost::asio::connect(socket, endpoints);
		
		std::cout << "Successfully connected to localhost:8888" << std::endl;
		socket.close();
	}
	catch (std::exception& e)
	{
		std::cout << "Connection test failed: " << e.what() << std::endl;
	}
}

void Client::testCryptoPPConnection()
{
	try
	{
		std::cout << "Testing Crypto++ functionality..." << std::endl;
		
		// Generate a random key and IV
		CryptoPP::AutoSeededRandomPool rng;
		CryptoPP::SecByteBlock key(CryptoPP::AES::DEFAULT_KEYLENGTH);
		CryptoPP::SecByteBlock iv(CryptoPP::AES::BLOCKSIZE);
		rng.GenerateBlock(key, key.size());
		rng.GenerateBlock(iv, iv.size());
		
		// Test data
		std::string plaintext = "Hello Crypto++!";
		std::string ciphertext, recovered;
		
		// Encryption
		CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption encryption;
		encryption.SetKeyWithIV(key, key.size(), iv);
		
		CryptoPP::StringSource(plaintext, true,
			new CryptoPP::StreamTransformationFilter(encryption,
				new CryptoPP::StringSink(ciphertext)
			)
		);
		
		// Decryption
		CryptoPP::CBC_Mode<CryptoPP::AES>::Decryption decryption;
		decryption.SetKeyWithIV(key, key.size(), iv);
		
		CryptoPP::StringSource(ciphertext, true,
			new CryptoPP::StreamTransformationFilter(decryption,
				new CryptoPP::StringSink(recovered)
			)
		);
		
		if (plaintext == recovered)
		{
			std::cout << "Successfully tested Crypto++ AES encryption/decryption" << std::endl;
		}
		else
		{
			std::cout << "Crypto++ test failed: decryption mismatch" << std::endl;
		}
	}
	catch (std::exception& e)
	{
		std::cout << "Crypto++ test failed: " << e.what() << std::endl;
	}
}