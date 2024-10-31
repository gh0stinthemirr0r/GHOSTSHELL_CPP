// command.cpp
// File Path: ghostshell/CommandRouter/command.cpp
#include "command.h"
#include <oqs/oqs.h>
#include <iostream>
#include <vector>      // Include vector for std::vector
#include <cstdint>     // Include cstdint for uint8_t

Command::Command(const std::string& name, const std::string& description, const std::function<void(const std::string&)>& execute)
    : name(name), description(description), execute(execute) {
}

Command::~Command() {
    // Destructor implementation if needed
}

bool Command::Execute(const std::string& parameters) {
    std::string encryptedParameters;
    if (!EncryptParameters(parameters, encryptedParameters)) {
        errorHandler.HandleError("Execute", "Failed to encrypt command parameters.");
        return false;
    }

    // Decrypt parameters before executing the command
    std::string decryptedParameters;
    if (!DecryptParameters(encryptedParameters, decryptedParameters)) {
        errorHandler.HandleError("Execute", "Failed to decrypt command parameters.");
        return false;
    }

    try {
        execute(decryptedParameters);
    }
    catch (const std::exception& e) {
        errorHandler.HandleError("Execute", "Command execution failed: " + std::string(e.what()));
        return false;
    }

    return true;
}

std::string Command::GetName() const {
    return name;
}

std::string Command::GetDescription() const {
    return description;
}

bool Command::EncryptParameters(const std::string& parameters, std::string& encryptedParameters) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptParameters", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;
    std::string privateKey; // Added to hold private key for completeness
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

    // GenerateVaultKeyPair should generate both public and private keys
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("EncryptParameters", "Failed to generate key pair for encryption.");
        OQS_KEM_free(kem);
        return false;
    }

    // Encrypt (encapsulate) using the public key
    if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), reinterpret_cast<const uint8_t*>(publicKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptParameters", "Failed to encapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    // Store the ciphertext and shared secret as the encrypted content
    encryptedParameters = std::string(ciphertext.begin(), ciphertext.end()) + std::string(sharedSecret.begin(), sharedSecret.end());

    OQS_KEM_free(kem);
    return true;
}

bool Command::DecryptParameters(const std::string& encryptedParameters, std::string& decryptedParameters) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptParameters", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;  // For consistency with keypair generation
    std::string privateKey;

    // Split encryptedParameters into ciphertext and sharedSecret components
    size_t ciphertextLength = kem->length_ciphertext;
    size_t sharedSecretLength = kem->length_shared_secret;

    if (encryptedParameters.size() != ciphertextLength + sharedSecretLength) {
        errorHandler.HandleError("DecryptParameters", "Invalid encrypted parameters length.");
        OQS_KEM_free(kem);
        return false;
    }

    std::vector<uint8_t> ciphertext(encryptedParameters.begin(), encryptedParameters.begin() + ciphertextLength);
    std::vector<uint8_t> sharedSecret(encryptedParameters.begin() + ciphertextLength, encryptedParameters.end());

    decryptedParameters.resize(sharedSecretLength);

    // Retrieve the public and private keys to decrypt
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("DecryptParameters", "Failed to retrieve key pair for decryption.");
        OQS_KEM_free(kem);
        return false;
    }

    // Decrypt (decapsulate) using the private key
    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(&decryptedParameters[0]), ciphertext.data(), reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptParameters", "Failed to decapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    OQS_KEM_free(kem);
    return true;
}
