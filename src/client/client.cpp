#include "Client.h"	
#include <iostream>

void Client::run()
{
	std::cout << "Client version: " << _version << std::endl;
	
	while (true)
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
