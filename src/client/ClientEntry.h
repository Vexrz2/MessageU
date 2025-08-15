#pragma once
#include <string>
#include <array>

class ClientEntry
{
private:
    std::array<uint8_t, 16> _uuid;
    std::string _username;
    std::string _publicKey;
    std::string _symmetricKey;

public:
	ClientEntry() = default; // Default constructor
    ClientEntry(const std::array<uint8_t, 16>& id, const std::string& name, const std::string& pubKey, const std::string& symKey)
        : _uuid(id), _username(name), _publicKey(pubKey), _symmetricKey(symKey) {}
    const std::array<uint8_t, 16>& getUUID() const { return _uuid; }
    const std::string& getName() const { return _username; }
    const std::string& getPublicKey() const { return _publicKey; }
    const std::string& getSymmetricKey() const { return _symmetricKey; }
    void setName(const std::string& newName) { _username = newName; }
    void setPublicKey(const std::string& newPubKey) { _publicKey = newPubKey; }
	void setSymmetricKey(const std::string& newSymKey) { _symmetricKey = newSymKey; }
};

