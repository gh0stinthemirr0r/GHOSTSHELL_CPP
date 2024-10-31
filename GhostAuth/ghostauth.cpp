// ghostauth.cpp - Authentication Implementation for GhostShell
// File Path: ghostshell/ghostauth.cpp

#include "ghostauth.h"
#include "user_storage_manager.h"
#include <iostream>
#include <vector>
#include <oqs/oqs.h>

// Constructor - Initialize OQS library for key generation and load users from storage
GhostAuth::GhostAuth() {
    OQS_init();
    // Load existing users from persistent storage
    userStorageManager.LoadUsers(userKeys);
}

// Destructor - Clean up OQS library resources and save users to storage
GhostAuth::~GhostAuth() {
    // Save users to persistent storage before destroying
    userStorageManager.SaveUsers(userKeys);
    OQS_destroy();
}

// Generate a post-quantum key pair using Kyber-512
bool GhostAuth::GeneratePostQuantumKeyPair(std::string& publicKey, std::string& privateKey) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        std::cerr << "Failed to initialize Kyber for key pair generation." << std::endl;
        return false;
    }

    // Create vectors to hold the generated public and private keys
    std::vector<uint8_t> publicKeyVec(kem->length_public_key);
    std::vector<uint8_t> privateKeyVec(kem->length_secret_key);

    if (OQS_KEM_keypair(kem, publicKeyVec.data(), privateKeyVec.data()) != OQS_SUCCESS) {
        std::cerr << "Failed to generate Kyber key pair." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    // Convert the key vectors to strings for easy handling
    publicKey.assign(publicKeyVec.begin(), publicKeyVec.end());
    privateKey.assign(privateKeyVec.begin(), privateKeyVec.end());

    // Free the KEM structure
    OQS_KEM_free(kem);
    return true;
}

// Add a new user and generate a key pair for them
bool GhostAuth::AddUser(const std::string& username) {
    std::string publicKey, privateKey;
    if (!GeneratePostQuantumKeyPair(publicKey, privateKey)) {
        std::cerr << "Failed to generate key pair for user: " << username << std::endl;
        return false;
    }

    // Store the key pair in the userKeys map
    userKeys[username] = { publicKey, privateKey };

    // Save the new user to persistent storage
    userStorageManager.SaveUsers(userKeys);
    return true;
}

// Authenticate a user using their signature
bool GhostAuth::AuthenticateUser(const std::string& username, const std::string& signature) {
    std::string publicKey;
    if (!GetUserPublicKey(username, publicKey)) {
        std::cerr << "Failed to retrieve public key for user: " << username << std::endl;
        return false;
    }

    // Using Dilithium-2 to verify the provided signature
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        std::cerr << "Failed to initialize Dilithium for signature verification." << std::endl;
        return false;
    }

    std::string message = "Authenticate user: " + username; // The message that was signed

    // Verify the signature using the public key
    bool isVerified = (OQS_SIG_verify(sig,
        reinterpret_cast<const uint8_t*>(message.c_str()), message.size(),
        reinterpret_cast<const uint8_t*>(signature.c_str()), signature.size(),
        reinterpret_cast<const uint8_t*>(publicKey.c_str())) == OQS_SUCCESS);

    OQS_SIG_free(sig);

    if (!isVerified) {
        std::cerr << "Signature verification failed for user: " << username << std::endl;
        return false;
    }

    return true;
}

// Retrieve the public key of a user
bool GhostAuth::GetUserPublicKey(const std::string& username, std::string& publicKey) const {
    auto it = userKeys.find(username);
    if (it == userKeys.end()) {
        std::cerr << "Public key not found for user: " << username << std::endl;
        return false;
    }
    publicKey = it->second.first;
    return true;
}

// Retrieve the private key securely by verifying user authorization
bool GhostAuth::GetAuthorizedPrivateKey(const std::string& username, std::string& privateKey) const {
    auto it = userKeys.find(username);
    if (it == userKeys.end()) {
        std::cerr << "Private key not found for user: " << username << std::endl;
        return false;
    }
    privateKey = it->second.second;
    return true;
}

// Sign a message with the user's private key using Dilithium-2
bool GhostAuth::SignMessage(const std::string& username, const std::string& message, std::string& signature) {
    std::string privateKey;
    if (!GetAuthorizedPrivateKey(username, privateKey)) {
        std::cerr << "Failed to retrieve private key for user: " << username << std::endl;
        return false;
    }

    // Initialize the signature mechanism (Dilithium-2)
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        std::cerr << "Failed to initialize Dilithium for message signing." << std::endl;
        return false;
    }

    signature.resize(sig->length_signature);
    size_t signature_len;

    // Sign the message using the user's private key
    if (OQS_SIG_sign(sig, reinterpret_cast<uint8_t*>(&signature[0]), &signature_len,
        reinterpret_cast<const uint8_t*>(message.c_str()), message.size(),
        reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        std::cerr << "Failed to sign the message for user: " << username << std::endl;
        OQS_SIG_free(sig);
        return false;
    }

    signature.resize(signature_len);
    OQS_SIG_free(sig);
    return true;
}
