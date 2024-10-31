// ghostauth_mfa.cpp - Post-Quantum Edition
#include "ghostauth_mfa.h"
#include <iostream>
#include <vector>
#include <oqs/oqs.h>
#include <random>
#include <chrono>

// Constructor
GhostAuthMFA::GhostAuthMFA() {
    // Constructor implementation
}

// Destructor
GhostAuthMFA::~GhostAuthMFA() {
    // Destructor implementation
}

// Verify MFA token function
bool GhostAuthMFA::VerifyMFAToken(const std::string& username, const std::string& token) const {
    std::cout << "Verifying MFA token for user: " << username << " with token: " << token << std::endl;
    std::lock_guard<std::mutex> lock(mfaMutex);

    auto it = userMFA.find(username);
    if (it == userMFA.end()) {
        const_cast<ErrorHandler&>(errorHandler).HandleError("VerifyMFAToken", "Username not found.");
        return false;
    }

    if (!IsMFATokenValid(it->second, token)) {
        const_cast<ErrorHandler&>(errorHandler).HandleError("VerifyMFAToken", "Invalid MFA token.");
        return false;
    }

    return true;
}

// Check if MFA token is valid function
bool GhostAuthMFA::IsMFATokenValid(const UserMFA& userMFA, const std::string& token) const {
    std::cout << "Checking if MFA token is valid: " << token << std::endl;

    // Ensure the token is still within the valid expiry time
    if (std::time(nullptr) > userMFA.tokenExpiry) {
        const_cast<ErrorHandler&>(errorHandler).HandleError("IsMFATokenValid", "MFA token has expired.");
        return false;
    }

    return userMFA.mfaToken == token;
}

// Generate a quantum-safe token function
bool GhostAuthMFA::QuantumSafeGenerateToken(std::string& token) {
    // Use a quantum-safe key encapsulation mechanism to generate a secure token
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        std::cerr << "QuantumSafeGenerateToken: Failed to initialize quantum-safe KEM." << std::endl;
        return false;
    }

    std::vector<uint8_t> publicKey(kem->length_public_key);
    std::vector<uint8_t> privateKey(kem->length_secret_key);
    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret);

    if (OQS_KEM_keypair(kem, publicKey.data(), privateKey.data()) != OQS_SUCCESS) {
        std::cerr << "QuantumSafeGenerateToken: Failed to generate quantum-safe key pair." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    if (OQS_KEM_encaps(kem, ciphertext.data(), sharedSecret.data(), publicKey.data()) != OQS_SUCCESS) {
        std::cerr << "QuantumSafeGenerateToken: Failed to encapsulate shared secret." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    token.assign(sharedSecret.begin(), sharedSecret.end());
    OQS_KEM_free(kem);

    return true;
}

// Enable MFA for a user
bool GhostAuthMFA::EnableMFA(const std::string& username) {
    std::lock_guard<std::mutex> lock(mfaMutex);
    userMFA[username].mfaEnabled = true;
    return true;
}

// Disable MFA for a user
bool GhostAuthMFA::DisableMFA(const std::string& username) {
    std::lock_guard<std::mutex> lock(mfaMutex);
    userMFA[username].mfaEnabled = false;
    return true;
}

// Generate an MFA token for a user
bool GhostAuthMFA::GenerateMFAToken(const std::string& username, std::string& token) {
    std::lock_guard<std::mutex> lock(mfaMutex);
    if (!userMFA[username].mfaEnabled) {
        const_cast<ErrorHandler&>(errorHandler).HandleError("GenerateMFAToken", "MFA not enabled for user.");
        return false;
    }

    if (!QuantumSafeGenerateToken(token)) {
        const_cast<ErrorHandler&>(errorHandler).HandleError("GenerateMFAToken", "Failed to generate quantum-safe MFA token.");
        return false;
    }

    userMFA[username].mfaToken = token;
    userMFA[username].tokenExpiry = std::time(nullptr) + 300; // Token valid for 5 minutes

    return true;
}
