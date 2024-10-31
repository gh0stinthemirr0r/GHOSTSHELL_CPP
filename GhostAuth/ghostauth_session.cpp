// ghostauth_session.cpp
// File Path: ghostshell/GhostAuth/ghostauth_session.cpp

#include "ghostauth_session.h"
#include <iostream>
#include <oqs/oqs.h>
#include <sstream>
#include <random>
#include <iomanip>

GhostAuthSession::GhostAuthSession() {
    // Initialize any session-specific parameters if necessary
}

GhostAuthSession::~GhostAuthSession() {
    // Clean up any resources used by the session
}

bool GhostAuthSession::StartSession(const std::string& username, const std::string& signature) {
    std::lock_guard<std::mutex> lock(sessionMutex);

    if (activeSessions.find(username) != activeSessions.end()) {
        errorHandler.HandleError("StartSession", "Session already exists for user: " + username);
        return false;
    }

    // Verify the quantum-safe signature of the user
    std::string message = "StartSession";
    if (!VerifyQuantumSafeSignature(activeSessions[username].publicKey, message, signature)) {
        errorHandler.HandleError("StartSession", "Signature verification failed for user: " + username);
        return false;
    }

    // Generate a secure session token
    std::string sessionToken = GenerateSessionToken(username);
    if (sessionToken.empty()) {
        errorHandler.HandleError("StartSession", "Failed to generate session token for user: " + username);
        return false;
    }

    // Create and store the session
    Session newSession;
    newSession.sessionToken = sessionToken;
    newSession.publicKey = activeSessions[username].publicKey;
    newSession.isActive = true;
    activeSessions[username] = newSession;

    std::cout << "[GhostAuthSession] Session started successfully for user: " << username << std::endl;
    return true;
}

bool GhostAuthSession::EndSession(const std::string& username) {
    std::lock_guard<std::mutex> lock(sessionMutex);

    auto it = activeSessions.find(username);
    if (it == activeSessions.end()) {
        errorHandler.HandleError("EndSession", "No active session found for user: " + username);
        return false;
    }

    activeSessions.erase(it);
    std::cout << "[GhostAuthSession] Session ended for user: " << username << std::endl;
    return true;
}

bool GhostAuthSession::VerifySession(const std::string& sessionToken) {
    std::lock_guard<std::mutex> lock(sessionMutex);

    for (const auto& session : activeSessions) {
        if (session.second.sessionToken == sessionToken && session.second.isActive) {
            return true;
        }
    }
    errorHandler.HandleError("VerifySession", "Invalid or inactive session token.");
    return false;
}

std::string GhostAuthSession::GenerateSessionToken(const std::string& username) {
    // Using a standard random generation technique to generate a session token
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    uint8_t randomBytes[32];
    for (auto& byte : randomBytes) {
        byte = static_cast<uint8_t>(dis(gen));
    }

    // Convert random bytes to a hex string as the session token
    std::ostringstream tokenStream;
    for (size_t i = 0; i < sizeof(randomBytes); ++i) {
        tokenStream << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(randomBytes[i]);
    }

    return tokenStream.str();
}

bool GhostAuthSession::GenerateQuantumSafeKeyPair(std::string& publicKey, std::string& privateKey) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("GenerateQuantumSafeKeyPair", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }

    // Allocate memory for public and private key buffers
    std::vector<uint8_t> publicKeyBuffer(sig->length_public_key);
    std::vector<uint8_t> privateKeyBuffer(sig->length_secret_key);

    // Generate the key pair
    if (OQS_SIG_keypair(sig, publicKeyBuffer.data(), privateKeyBuffer.data()) != OQS_SUCCESS) {
        errorHandler.HandleError("GenerateQuantumSafeKeyPair", "Failed to generate quantum-safe key pair.");
        OQS_SIG_free(sig);
        return false;
    }

    // Convert key buffers to std::string
    publicKey.assign(publicKeyBuffer.begin(), publicKeyBuffer.end());
    privateKey.assign(privateKeyBuffer.begin(), privateKeyBuffer.end());

    OQS_SIG_free(sig);
    return true;
}

bool GhostAuthSession::VerifyQuantumSafeSignature(const std::string& publicKey, const std::string& message, const std::string& signature) {
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("VerifyQuantumSafeSignature", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }

    // Convert publicKey, message, and signature to uint8_t*
    const uint8_t* publicKeyPtr = reinterpret_cast<const uint8_t*>(publicKey.data());
    const uint8_t* messagePtr = reinterpret_cast<const uint8_t*>(message.data());
    const uint8_t* signaturePtr = reinterpret_cast<const uint8_t*>(signature.data());

    bool isVerified = (OQS_SIG_verify(sig, messagePtr, message.size(),
        signaturePtr, signature.size(),
        publicKeyPtr) == OQS_SUCCESS);

    OQS_SIG_free(sig);
    return isVerified;
}
