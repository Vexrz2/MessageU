#include "ClientEntry.h"

ClientEntry::ClientEntry(const std::array<uint8_t, 16>& id, const std::string& name, const std::string& pubKey, const std::string& symKey)
	: _uuid(id), _username(name), _publicKey(pubKey), _symmetricKey(symKey) 
{
}

const std::array<uint8_t, 16>& ClientEntry::getUUID() const
{
	return _uuid;
}

const std::string& ClientEntry::getName() const
{
	return _username;
}

const std::string& ClientEntry::getPublicKey() const
{
	return _publicKey;
}

const std::string& ClientEntry::getSymmetricKey() const
{
	return _symmetricKey;
}

void ClientEntry::setName(const std::string& newName)
{
	_username = newName;
}

void ClientEntry::setPublicKey(const std::string& newPubKey)
{
	_publicKey = newPubKey;
}

void ClientEntry::setSymmetricKey(const std::string& newSymKey)
{
	_symmetricKey = newSymKey;
}