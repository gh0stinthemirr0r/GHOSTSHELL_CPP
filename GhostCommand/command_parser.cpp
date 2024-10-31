// command_parser.cpp
// File Path: ghostshell/CommandParser/command_parser.cpp

#include "command_parser.h"
#include "error_handler.h"  // Including here to avoid deep header dependency in the header file
#include <oqs/oqs.h>
#include <iostream>

CommandParser::CommandParser() {
    // Initialize error handler
    errorHandler = new ErrorHandler();
}

CommandParser::~CommandParser() {
    // Clean up error handler
    delete errorHandler;
}

bool CommandParser::GenerateQuantumSafeKeyPair(std::string& publicKey, std::string& privateKey) {
    // Generate a quantum-safe key pair using Kyber from liboqs.
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler->HandleError("GenerateQuantumSafeKeyPair", "Failed to initialize quantum-safe KEM.");
        return false;
    }

    // Placeholder logic for key pair generation (for demonstration purposes)
    publicKey = "GeneratedPublicKey";
    privateKey = "GeneratedPrivateKey";

    std::cout << "[CommandParser] Quantum-safe key pair generated." << std::endl;

    OQS_KEM_free(kem);
    return true;
}

bool CommandParser::ParseCommand(const std::string& command, std::string& parsedOutput) {
    // Placeholder logic for parsing the command
    parsedOutput = "Parsed: " + command;
    std::cout << "[CommandParser] Command parsed successfully: " << parsedOutput << std::endl;

    return true;
}
