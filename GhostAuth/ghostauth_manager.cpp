#include <iostream>
#include <string>
#include <vector>
#include <cstdint>
#include <oqs/oqs.h>
#include "ghostauth_manager.h"
#include "ghostauth.h"
#include "ghostvault.h"
#include "error_handler.h"

// Constructor now takes a reference to GhostAuth and initializes properly.
GhostAuthManager::GhostAuthManager(GhostAuth& authRef) : ghostAuth(authRef) {
    // Constructor implementation if needed
}

GhostAuthManager::~GhostAuthManager() {
    // Destructor implementation if needed
}

bool GhostAuthManager::GenerateMFAToken(const std::string& username, std::string& token) {
    // Initialize the quantum-safe signature scheme (Dilithium-2)
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("GenerateMFAToken", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }

    // Define the MFA message that will be signed
    std::string message = "MFA request for user: " + username;
    token.resize(sig->length_signature);
    size_t token_len;

    // Retrieve the private key securely, ensuring proper authorization
    std::string privateKey;
    if (!ghostAuth.GetAuthorizedPrivateKey(username, privateKey)) {
        errorHandler.HandleError("GenerateMFAToken", "Private key not found or unauthorized access for user: " + username);
        OQS_SIG_free(sig);
        return false;
    }

    // Sign the message with the retrieved private key using quantum-safe signature
    if (OQS_SIG_sign(sig, reinterpret_cast<uint8_t*>(&token[0]), &token_len,
        reinterpret_cast<const uint8_t*>(message.c_str()), message.size(),
        reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("GenerateMFAToken", "Failed to sign MFA token.");
        OQS_SIG_free(sig);
        return false;
    }

    // Resize the token to the actual length of the signature
    token.resize(token_len);
    OQS_SIG_free(sig);
    return true;
}

bool GhostAuthManager::VerifyMFAToken(const std::string& username, const std::string& token) {
    // Initialize the quantum-safe signature scheme (Dilithium-2)
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("VerifyMFAToken", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }

    // Retrieve the public key for the user
    std::string publicKey;
    if (!ghostAuth.GetUserPublicKey(username, publicKey)) {
        errorHandler.HandleError("VerifyMFAToken", "Failed to retrieve public key for user: " + username);
        OQS_SIG_free(sig);
        return false;
    }

    // Define the message that was signed to generate the MFA token
    std::string message = "MFA request for user: " + username;

    // Verify the MFA token (signature) with the user's public key
    bool isVerified = (OQS_SIG_verify(sig,
        reinterpret_cast<const uint8_t*>(message.c_str()), message.size(),
        reinterpret_cast<const uint8_t*>(token.c_str()), token.size(),
        reinterpret_cast<const uint8_t*>(publicKey.c_str())) == OQS_SUCCESS);

    if (!isVerified) {
        errorHandler.HandleError("VerifyMFAToken", "Signature verification failed for MFA token of user: " + username);
    }

    OQS_SIG_free(sig);
    return isVerified;
}
