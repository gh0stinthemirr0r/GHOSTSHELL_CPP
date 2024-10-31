// command_router.cpp
// File Path: ghostshell/CommandRouter/command_router.cpp

#include "command_router.h"
#include <iostream>
#include <oqs/oqs.h>

// Constructor for CommandRouter
CommandRouter::CommandRouter() {
    ghostAuth = std::make_shared<GhostAuth>();
    // Initialize cryptoManager as well if necessary.
}

// Destructor for CommandRouter
CommandRouter::~CommandRouter() {
    // Destructor implementation if needed.
}

// Register a command with its handler function.
bool CommandRouter::RegisterCommand(const std::string& commandName, std::function<bool(const std::string&, std::string&)> handler) {
    std::lock_guard<std::mutex> lock(commandMutex); // Ensuring thread safety
    if (commandRegistry.find(commandName) != commandRegistry.end()) {
        errorHandler.HandleError("RegisterCommand", "Command already registered: " + commandName);
        return false;
    }
    commandRegistry[commandName] = handler;
    std::cout << "[CommandRouter] Registered command: " << commandName << std::endl;
    return true;
}

// Execute a registered command with quantum-safe encryption and authentication.
bool CommandRouter::ExecuteCommand(const std::string& username, const std::string& command, std::string& output) {
    if (!AuthenticateUser(username)) {
        errorHandler.HandleError("ExecuteCommand", "Authentication failed for user: " + username);
        return false;
    }

    // Encrypt the command before routing it.
    std::string encryptedCommand;
    std::string publicKey;
    std::string privateKey;

    // Generate a post-quantum key pair.
    if (!cryptoManager.GenerateKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("ExecuteCommand", "Failed to generate key pair for encryption.");
        return false;
    }

    // Encrypt the command using the public key.
    if (!cryptoManager.Encrypt(command, publicKey, encryptedCommand)) {
        errorHandler.HandleError("ExecuteCommand", "Failed to encrypt command: " + command);
        return false;
    }

    auto it = commandRegistry.find(command);
    if (it == commandRegistry.end()) {
        errorHandler.HandleError("ExecuteCommand", "Command not found: " + command);
        return false;
    }

    // Decrypt the command to execute it.
    std::string decryptedCommand;
    if (!DecryptCommand(encryptedCommand, decryptedCommand, privateKey)) {
        errorHandler.HandleError("ExecuteCommand", "Failed to decrypt command: " + command);
        return false;
    }

    // Execute the command handler.
    return it->second(username, output);
}

// Authenticate a user using post-quantum signature verification.
bool CommandRouter::AuthenticateUser(const std::string& username) {
    std::string publicKey, signature, message = "AuthenticateUser";

    if (!ghostAuth->GetUserPublicKey(username, publicKey)) {
        errorHandler.HandleError("AuthenticateUser", "Failed to retrieve public key for user: " + username);
        return false;
    }

    // Use `SignMessage()` to generate a signature for authentication.
    if (!ghostAuth->SignMessage(username, message, signature)) {
        errorHandler.HandleError("AuthenticateUser", "Failed to retrieve signature for user: " + username);
        return false;
    }

    // Quantum-safe signature verification using Dilithium from liboqs.
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("AuthenticateUser", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }

    bool isVerified = (OQS_SIG_verify(sig,
        reinterpret_cast<const uint8_t*>(message.c_str()), message.size(),
        reinterpret_cast<const uint8_t*>(signature.c_str()), signature.size(),
        reinterpret_cast<const uint8_t*>(publicKey.c_str())) == OQS_SUCCESS);

    OQS_SIG_free(sig);

    if (!isVerified) {
        errorHandler.HandleError("AuthenticateUser", "Signature verification failed for user: " + username);
        return false;
    }

    std::cout << "[CommandRouter] User authenticated successfully: " << username << std::endl;
    return true;
}

// Decrypt an encrypted command.
bool CommandRouter::DecryptCommand(const std::string& encryptedCommand, std::string& decryptedCommand, const std::string& privateKey) {
    if (!cryptoManager.Decrypt(encryptedCommand, privateKey, decryptedCommand)) {
        errorHandler.HandleError("DecryptCommand", "Failed to decrypt command data.");
        return false;
    }
    return true;
}
