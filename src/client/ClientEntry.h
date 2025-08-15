#pragma once
#include <string>

class ClientEntry
{
private:
    std::string _uniqueId;
    std::string _username;
    std::string _publicKey;
    std::string _symmetricKey;

public:
	ClientEntry() = default; // Default constructor
    ClientEntry(const std::string& id, const std::string& name, const std::string& pubKey, const std::string& symKey)
        : _uniqueId(id), _username(name), _publicKey(pubKey), _symmetricKey(symKey) {}
    const std::string& getUniqueId() const { return _uniqueId; }
    const std::string& getName() const { return _username; }
    const std::string& getPublicKey() const { return _publicKey; }
    const std::string& getSymmetricKey() const { return _symmetricKey; }
    void setName(const std::string& newName) { _username = newName; }
    void setPublicKey(const std::string& newPubKey) { _publicKey = newPubKey; }
	void setSymmetricKey(const std::string& newSymKey) { _symmetricKey = newSymKey; }
};

