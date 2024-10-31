// crypto_manager.h

#ifndef CRYPTO_MANAGER_H
#define CRYPTO_MANAGER_H

#include <string>
#include <oqs/oqs.h>

class CryptoManager {
public:
    CryptoManager();
    ~CryptoManager();

    bool GenerateKeyPair(std::string& publicKey, std::string& privateKey);
    bool Encrypt(const std::string& plaintext, const std::string& publicKey, std::string& encryptedOutput);
    bool Decrypt(const std::string& encryptedInput, const std::string& privateKey, std::string& decryptedOutput);
};

#endif // CRYPTO_MANAGER_H
