// crypto_manager.cpp

#include "crypto_manager.h"
#include <oqs/oqs.h>
#include <iostream>
#include <vector>
#include <sstream>

CryptoManager::CryptoManager() {
    // Constructor - initialize anything if needed
    OQS_init();
}

CryptoManager::~CryptoManager() {
    // Destructor - cleanup OQS resources
    OQS_destroy();
}

// Generate a post-quantum key pair using Kyber
bool CryptoManager::GenerateKeyPair(std::string& publicKey, std::string& privateKey) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        std::cerr << "Failed to initialize Kyber for key pair generation." << std::endl;
        return false;
    }

    std::vector<uint8_t> publicKeyVec(kem->length_public_key);
    std::vector<uint8_t> privateKeyVec(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, publicKeyVec.data(), privateKeyVec.data()) != OQS_SUCCESS) {
        std::cerr << "Failed to generate Kyber key pair." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    // Convert the keys to strings
    publicKey.assign(publicKeyVec.begin(), publicKeyVec.end());
    privateKey.assign(privateKeyVec.begin(), privateKeyVec.end());

    OQS_KEM_free(kem);
    return true;
}

// Encrypt a plaintext using the public key
bool CryptoManager::Encrypt(const std::string& plaintext, const std::string& publicKey, std::string& encryptedOutput) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        std::cerr << "Failed to initialize Kyber for encryption." << std::endl;
        return false;
    }

    // Allocate memory for ciphertext and shared secret
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

    if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), reinterpret_cast<const uint8_t*>(publicKey.c_str())) != OQS_SUCCESS) {
        std::cerr << "Failed to encapsulate message." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    // Convert ciphertext to a string format
    encryptedOutput.assign(ciphertext.begin(), ciphertext.end());
    OQS_KEM_free(kem);
    return true;
}

// Decrypt a ciphertext using the private key
bool CryptoManager::Decrypt(const std::string& encryptedInput, const std::string& privateKey, std::string& decryptedOutput) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        std::cerr << "Failed to initialize Kyber for decryption." << std::endl;
        return false;
    }

    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, sharedSecret.data(), reinterpret_cast<const uint8_t*>(encryptedInput.c_str()), reinterpret_cast<const uint8_t*>(privateKey.c_str())) != OQS_SUCCESS) {
        std::cerr << "Failed to decapsulate message." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    // Convert the shared secret to a string format
    decryptedOutput.assign(sharedSecret.begin(), sharedSecret.end());
    OQS_KEM_free(kem);
    return true;
}
