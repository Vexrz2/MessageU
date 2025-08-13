#pragma once
#include <string>

class ClientEntry
{
private:
    std::string uniqueId;
    std::string name;
    std::string publicKey;
    std::string symmetricKey;

public:
    ClientEntry(const std::string& id, const std::string& name, const std::string& pubKey, const std::string& symKey)
        : uniqueId(id), name(name), publicKey(pubKey), symmetricKey(symKey) {}
    const std::string& getUniqueId() const { return uniqueId; }
    const std::string& getName() const { return name; }
    const std::string& getPublicKey() const { return publicKey; }
    const std::string& getSymmetricKey() const { return symmetricKey; }
    void setName(const std::string& newName) { name = newName; }
    void setPublicKey(const std::string& newPubKey) { publicKey = newPubKey; }
	void setSymmetricKey(const std::string& newSymKey) { symmetricKey = newSymKey; }
};

