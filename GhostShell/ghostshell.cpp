// ghostshell.cpp - Main File for GhostShell
// File Path: ghostshell/ghostshell.cpp

#include "ghostshell.h"
#include <iostream>
#include <oqs/oqs.h>

// Constructor for GhostShell
GhostShell::GhostShell()
    : ghostAuth(std::make_shared<GhostAuth>()),
    oqsSig(OQS_SIG_new(OQS_SIG_alg_dilithium_2), OQS_SIG_free)
{
    // Initialize the Open Quantum Safe library for post-quantum security
    if (oqsSig == nullptr) {
        errorHandler.HandleError("GhostShell Constructor", "Failed to initialize Dilithium signature mechanism.");
    }
    OQS_init();
}

// Destructor for GhostShell
GhostShell::~GhostShell() {
    // Clean up the OQS library resources
    OQS_destroy();
}

// Main execution loop for GhostShell
void GhostShell::Run() {
    std::cout << "Welcome to GhostShell!" << std::endl;

    // Authentication Flow
    std::string username;
    std::string signature;

    std::cout << "Enter username: ";
    std::getline(std::cin, username);

    // Register or authenticate the user
    if (!ghostAuth->AddUser(username)) {
        // Authenticate existing user
        std::cout << "Existing user detected. Please authenticate.\nEnter signature for authentication: ";
        std::getline(std::cin, signature);

        if (!ghostAuth->AuthenticateUser(username, signature)) {
            errorHandler.HandleError("Run", "Authentication failed for user: " + username);
            std::cerr << "Authentication failed. Exiting..." << std::endl;
            return;
        }
    }
    else {
        std::cout << "New user registered successfully. The system is now quantum-safe." << std::endl;
    }

    std::cout << "Authentication successful. Welcome, " << username << "!" << std::endl;

    // Command execution loop
    std::string command;
    while (true) {
        std::cout << "> ";
        std::getline(std::cin, command);

        if (command == "exit") {
            break;
        }
        else {
            if (!commandHandler.processCommand(command)) {
                errorHandler.HandleError("Run", "Failed to process command: " + command);
                std::cerr << "Command execution failed." << std::endl;
            }
        }
    }

    std::cout << "Goodbye!" << std::endl;
}
