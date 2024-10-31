#pragma once
// command_authorization.h
#ifndef COMMANDAUTHORIZATION_H
#define COMMANDAUTHORIZATION_H

#include <string>
#include <map>
#include <memory>
#include <oqs/oqs.h>  // Include OQS for post-quantum cryptographic context
#include "error_handler.h"
#include "ghostauth.h"  // Include GhostAuth to ensure complete definition

class CommandAuthorization {
public:
    // Constructor and Destructor
    CommandAuthorization();
    ~CommandAuthorization();

    // Adds user permission for executing a specific command
    bool AddUserPermission(const std::string& username, const std::string& commandName);

    // Verifies whether a user is authorized to execute a specific command
    bool IsUserAuthorized(const std::string& username, const std::string& commandName);

private:
    // Initializes the post-quantum signature scheme
    void InitializePostQuantumSignature();

    // Verifies the user's signature to ensure authorization authenticity
    bool VerifyUserSignature(const std::string& username, const std::string& message, const std::string& signature);

    // Stores permissions per user and command
    std::map<std::string, std::map<std::string, bool>> userPermissions;

    // Handles any errors that arise during operations
    ErrorHandler errorHandler;

    // Shared pointer to manage GhostAuth instance, allowing user authentication tasks
    std::shared_ptr<GhostAuth> ghostAuth;

    // Unique pointer to manage OQS_SIG lifecycle for post-quantum signature operations
    std::unique_ptr<OQS_SIG, void(*)(OQS_SIG*)> oqsSig;
};

#endif // COMMANDAUTHORIZATION_H
