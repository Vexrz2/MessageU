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
    ClientEntry(const std::array<uint8_t, 16>& id, const std::string& name, const std::string& pubKey, const std::string& symKey);
    const std::array<uint8_t, 16>& getUUID() const;
    const std::string& getName() const;
    const std::string& getPublicKey() const;
    const std::string& getSymmetricKey() const;
    void setName(const std::string& newName);
    void setPublicKey(const std::string& newPubKey);
    void setSymmetricKey(const std::string& newSymKey);
};

