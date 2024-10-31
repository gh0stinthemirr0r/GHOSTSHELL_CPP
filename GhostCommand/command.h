#pragma once
// command.h
// File Path: ghostshell/CommandRouter/command.h
#ifndef COMMAND_H
#define COMMAND_H

#include <string>
#include <functional>
#include <map>
#include "error_handler.h"
#include "ghostvault.h"
#include <oqs/oqs.h>

class Command {
public:
    Command(const std::string& name, const std::string& description, const std::function<void(const std::string&)>& execute);
    ~Command();

    // Execute the command (removed const to allow modification of members)
    bool Execute(const std::string& parameters);

    // Get command information (left const as these do not modify members)
    std::string GetName() const;
    std::string GetDescription() const;

private:
    std::string name;
    std::string description;
    std::function<void(const std::string&)> execute;
    ErrorHandler errorHandler;
    GhostVault ghostVault;

    // Encrypt and decrypt methods for quantum-safe security (removed const to allow modification)
    bool EncryptParameters(const std::string& parameters, std::string& encryptedParameters);
    bool DecryptParameters(const std::string& encryptedParameters, std::string& decryptedParameters);
};

#endif // COMMAND_H
