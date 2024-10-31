// ghostshell.h - Core GhostShell Header
// File Path: ghostshell/ghostshell.h

#ifndef GHOSTSHELL_H
#define GHOSTSHELL_H

#include <string>
#include <memory>       // For std::shared_ptr and std::unique_ptr
#include "ghostauth.h"
#include "command_handler.h"
#include "error_handler.h"
#include <oqs/oqs.h>

class GhostShell {
public:
    GhostShell();
    ~GhostShell();

    // Runs the GhostShell core
    void Run();

    // Command execution interface with post-quantum secure authentication
    bool ExecuteCommand(const std::string& username, const std::string& command);

private:
    // Authentication and command handling
    bool AuthenticateAndExecute(const std::string& username, const std::string& command);
    bool QuantumSafeAuthenticateUser(const std::string& username, const std::string& message, const std::string& signature);

    // Members
    std::shared_ptr<GhostAuth> ghostAuth;  // Manages user authentication
    CommandHandler commandHandler;         // Manages command processing
    ErrorHandler errorHandler;             // Handles errors across the application
    std::unique_ptr<OQS_SIG, void(*)(OQS_SIG*)> oqsSig; // Post-quantum signature instance
};

#endif // GHOSTSHELL_H
