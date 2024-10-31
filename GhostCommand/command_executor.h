#pragma once
// command_executor.h
// File Path: ghostshell/CommandRouter/command_executor.h
#ifndef COMMAND_EXECUTOR_H
#define COMMAND_EXECUTOR_H

#include <string>
#include <vector>
#include <functional>
#include <map>
#include "error_handler.h"
#include "ghostvault.h"
#include <oqs/oqs.h>

class CommandExecutor {
public:
    CommandExecutor();
    ~CommandExecutor();

    // Register a command for execution
    bool RegisterCommand(const std::string& commandName, const std::function<void(const std::vector<std::string>&)>& handler);

    // Execute a command
    bool ExecuteCommand(const std::string& commandName, const std::vector<std::string>& parameters);

private:
    std::map<std::string, std::function<void(const std::vector<std::string>&)>> commandRegistry;
    ErrorHandler errorHandler;
    GhostVault ghostVault;

    // Helper methods for post-quantum secure handling
    bool EncryptCommand(const std::string& commandName, const std::vector<std::string>& parameters, std::string& encryptedCommand);
    bool DecryptCommand(const std::string& encryptedCommand, std::string& commandName, std::vector<std::string>& parameters);
};

#endif // COMMAND_EXECUTOR_H
