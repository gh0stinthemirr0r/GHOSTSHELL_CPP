// ghostvault.cpp - Post-Quantum Edition
// File Path: ghostshell/GhostVault/ghostvault.cpp

#include "ghostvault.h"
#include <oqs/oqs.h>
#include <iostream>
#include <sstream>
#include <cstring>
#include <mutex> // Include mutex for std::lock_guard

GhostVault::GhostVault() {
    // Generate a keypair for use within the vault on construction
    if (!GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("GhostVault", "Failed to generate vault keypair during initialization.");
    }
}

GhostVault::~GhostVault() {
    // Destructor implementation
}

bool GhostVault::StoreSecret(const std::string& key, const std::string& value) {
    std::lock_guard<std::mutex> lock(vaultMutex);
    std::string encryptedValue;
    if (!EncryptData(value, encryptedValue, publicKey)) {
        errorHandler.HandleError("StoreSecret", "Failed to encrypt secret: " + key);
        return false;
    }
    secrets[key] = encryptedValue;
    return true;
}

bool GhostVault::RetrieveSecret(const std::string& key, std::string& value) {
    std::lock_guard<std::mutex> lock(vaultMutex);
    auto it = secrets.find(key);
    if (it == secrets.end()) {
        errorHandler.HandleError("RetrieveSecret", "Secret not found: " + key);
        return false;
    }
    if (!DecryptData(it->second, value, privateKey)) {
        errorHandler.HandleError("RetrieveSecret", "Failed to decrypt secret: " + key);
        return false;
    }
    return true;
}

bool GhostVault::DeleteSecret(const std::string& key) {
    std::lock_guard<std::mutex> lock(vaultMutex);
    auto it = secrets.find(key);
    if (it == secrets.end()) {
        errorHandler.HandleError("DeleteSecret", "Secret not found: " + key);
        return false;
    }
    secrets.erase(it);
    return true;
}

bool GhostVault::GenerateVaultKeyPair(std::string& generatedPublicKey, std::string& generatedPrivateKey) {
    // Use OQS for generating post-quantum secure keypair
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("GenerateVaultKeyPair", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }
    generatedPublicKey.resize(sig->length_public_key);
    generatedPrivateKey.resize(sig->length_secret_key);

    if (OQS_SIG_keypair(sig, reinterpret_cast<uint8_t*>(&generatedPublicKey[0]), reinterpret_cast<uint8_t*>(&generatedPrivateKey[0])) != OQS_SUCCESS) {
        errorHandler.HandleError("GenerateVaultKeyPair", "Failed to generate quantum-safe key pair.");
        OQS_SIG_free(sig);
        return false;
    }

    OQS_SIG_free(sig);
    return true;
}

bool GhostVault::EncryptData(const std::string& data, std::string& encryptedData, const std::string& publicKey) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptData", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    encryptedData.resize(kem->length_ciphertext);
    std::string sharedSecret(kem->length_shared_secret, '\0');

    if (OQS_KEM_encaps(kem, reinterpret_cast<uint8_t*>(&encryptedData[0]), reinterpret_cast<uint8_t*>(&sharedSecret[0]), reinterpret_cast<const uint8_t*>(&publicKey[0])) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptData", "Failed to encapsulate data using quantum-safe encryption.");
        OQS_KEM_free(kem);
        return false;
    }

    // Use shared secret for encryption
    encryptedData = sharedSecret; // Placeholder to represent encrypted data

    OQS_KEM_free(kem);
    return true;
}

bool GhostVault::DecryptData(const std::string& encryptedData, std::string& decryptedData, const std::string& privateKey) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptData", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    decryptedData.resize(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(&decryptedData[0]), reinterpret_cast<const uint8_t*>(&encryptedData[0]), reinterpret_cast<const uint8_t*>(&privateKey[0])) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptData", "Failed to decapsulate shared secret using quantum-safe encryption.");
        OQS_KEM_free(kem);
        return false;
    }

    OQS_KEM_free(kem);
    return true;
}
