#pragma once
// command_router.h
#ifndef COMMAND_ROUTER_H
#define COMMAND_ROUTER_H

#include <string>
#include <functional>
#include <map>
#include <mutex>
#include <memory>
#include <oqs/oqs.h>  // Ensure OQS is included for post-quantum security.
#include "error_handler.h"
#include "ghostauth.h"  // Include GhostAuth for authentication functions
#include "crypto_manager.h"  // Include CryptoManager to handle cryptographic functions

class CommandRouter {
public:
    CommandRouter();
    ~CommandRouter();

    // Register a command with its corresponding handler.
    bool RegisterCommand(const std::string& commandName, std::function<bool(const std::string&, std::string&)> handler);

    // Execute the given command by routing it to the appropriate handler.
    bool ExecuteCommand(const std::string& username, const std::string& command, std::string& output);

private:
    // Map to store registered commands with their handler functions.
    std::map<std::string, std::function<bool(const std::string&, std::string&)>> commandRegistry;

    // Mutex to ensure thread-safe access to command registry.
    std::mutex commandMutex;

    // Components for handling authentication and cryptographic operations.
    std::shared_ptr<GhostAuth> ghostAuth;  // Use a shared pointer for the GhostAuth instance.
    CryptoManager cryptoManager;  // CryptoManager to handle encryption and decryption tasks.
    ErrorHandler errorHandler;  // Error handler for managing errors.

    // Authenticate user using quantum-safe methods.
    bool AuthenticateUser(const std::string& username);

    // Decrypt a command using the private key.
    bool DecryptCommand(const std::string& encryptedCommand, std::string& decryptedCommand, const std::string& privateKey);
};

#endif // COMMAND_ROUTER_H
