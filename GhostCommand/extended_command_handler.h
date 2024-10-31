// extended_command_handler.h - Post-Quantum Edition
// File Path: ghostshell/CommandRouter/extended_command_handler.h

#ifndef EXTENDED_COMMAND_HANDLER_H
#define EXTENDED_COMMAND_HANDLER_H

#include <string>
#include <vector>
#include <functional>
#include <map>
#include <mutex>
#include <memory>
#include "error_handler.h"
#include "ghostauth.h"
#include "crypto_manager.h"
#include "ghostvault.h" // Manages secure storage and key generation

class ExtendedCommandHandler {
public:
    ExtendedCommandHandler();
    ~ExtendedCommandHandler();

    bool RegisterSpecializedCommand(const std::string& commandName, const std::function<void(const std::vector<std::string>&)>& handler);
    bool ExecuteSpecializedCommand(const std::string& username, const std::string& commandName, const std::vector<std::string>& parameters);

private:
    bool AuthenticateUser(const std::string& username);
    bool EncryptCommand(const std::string& commandName, const std::vector<std::string>& parameters, std::string& encryptedCommand);
    bool DecryptCommand(const std::string& encryptedCommand, std::string& commandName, std::vector<std::string>& parameters);

    std::map<std::string, std::function<void(const std::vector<std::string>&)>> specializedCommandRegistry;

    std::shared_ptr<GhostAuth> ghostAuth;   // Updated to shared_ptr for shared ownership and better resource management
    CryptoManager cryptoManager;            // Handles encryption/decryption operations
    GhostVault ghostVault;                  // Handles secure storage and key management

    ErrorHandler errorHandler;              // Handles error reporting
    std::mutex handlerMutex;                // Synchronizes command execution
};

#endif // EXTENDED_COMMAND_HANDLER_H
