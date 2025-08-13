#include "Client.h"	
#include <iostream>
#include <boost/asio.hpp>

using boost::asio::ip::tcp;

void Client::run()
{
	std::cout << "Client version: " << _version << std::endl;
	
	// Test boost connection
	testBoostConnection();
	
	while (true)
	{
		promptForInput();
		int choice;
		std::cin >> choice;

		handle_client_input(choice);
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

void Client::handle_client_input(int choice)
{
	switch (choice)
	{
	case 110:
		std::cout << "Registering client..." << std::endl;
		// Registration logic here
		break;
	case 120:
		std::cout << "Requesting clients list..." << std::endl;
		// Request clients list logic here
		break;
	case 130:
		std::cout << "Requesting public key..." << std::endl;
		// Request public key logic here
		break;
	case 140:
		std::cout << "Requesting waiting messages..." << std::endl;
		// Request waiting messages logic here
		break;
	case 150:
		std::cout << "Sending a text message..." << std::endl;
		// Send text message logic here
		break;
	case 151:
		std::cout << "Sending request for symmetric key..." << std::endl;
		// Send request for symmetric key logic here
		break;
	case 152:
		std::cout << "Sending your symmetric key..." << std::endl;
		// Send symmetric key logic here
		break;
	case 0:
	default:
		std::cout << "Exiting client." << std::endl;
		exit(0);
	}
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
