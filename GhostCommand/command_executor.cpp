// command_executor.cpp
// File Path: ghostshell/CommandRouter/command_executor.cpp
#include "command_executor.h"
#include <iostream>
#include <oqs/oqs.h>
#include <sstream>
#include <vector>

CommandExecutor::CommandExecutor() {
    // Constructor implementation if needed
}

CommandExecutor::~CommandExecutor() {
    // Destructor implementation if needed
}

bool CommandExecutor::RegisterCommand(const std::string& commandName, const std::function<void(const std::vector<std::string>&)>& handler) {
    if (commandRegistry.find(commandName) != commandRegistry.end()) {
        errorHandler.HandleError("RegisterCommand", "Command already registered: " + commandName);
        return false;
    }
    commandRegistry[commandName] = handler;
    std::cout << "[CommandExecutor] Registered command: " << commandName << std::endl;
    return true;
}

bool CommandExecutor::ExecuteCommand(const std::string& commandName, const std::vector<std::string>& parameters) {
    // Encrypt the command and parameters before execution
    std::string encryptedCommand;
    if (!EncryptCommand(commandName, parameters, encryptedCommand)) {
        errorHandler.HandleError("ExecuteCommand", "Failed to encrypt command.");
        return false;
    }

    // Decrypt the command and parameters before actually executing
    std::string decryptedCommandName;
    std::vector<std::string> decryptedParameters;
    if (!DecryptCommand(encryptedCommand, decryptedCommandName, decryptedParameters)) {
        errorHandler.HandleError("ExecuteCommand", "Failed to decrypt command.");
        return false;
    }

    auto it = commandRegistry.find(decryptedCommandName);
    if (it == commandRegistry.end()) {
        errorHandler.HandleError("ExecuteCommand", "Command not found: " + decryptedCommandName);
        return false;
    }

    try {
        it->second(decryptedParameters);
    }
    catch (const std::exception& e) {
        errorHandler.HandleError("ExecuteCommand", "Command execution failed: " + std::string(e.what()));
        return false;
    }

    return true;
}

bool CommandExecutor::EncryptCommand(const std::string& commandName, const std::vector<std::string>& parameters, std::string& encryptedCommand) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptCommand", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;
    std::string privateKey; // Added for completeness to use for key pair generation
    std::vector<uint8_t> sharedSecret(kem->length_shared_secret, '\0');
    encryptedCommand.resize(kem->length_ciphertext);

    // Serialize the command name and parameters
    std::ostringstream oss;
    oss << commandName;
    for (const auto& param : parameters) {
        oss << " " << param;
    }
    std::string commandData = oss.str();

    // GenerateVaultKeyPair should generate and set a proper keypair in GhostVault
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("EncryptCommand", "Failed to generate key pair for encryption.");
        OQS_KEM_free(kem);
        return false;
    }

    if (OQS_KEM_encaps(kem, reinterpret_cast<uint8_t*>(&encryptedCommand[0]), sharedSecret.data(), reinterpret_cast<const uint8_t*>(publicKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptCommand", "Failed to encapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    encryptedCommand = std::string(sharedSecret.begin(), sharedSecret.end()); // Simulate encrypted content with shared secret
    OQS_KEM_free(kem);
    return true;
}

bool CommandExecutor::DecryptCommand(const std::string& encryptedCommand, std::string& commandName, std::vector<std::string>& parameters) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptCommand", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;  // For consistency with keypair generation
    std::string privateKey;
    std::string decryptedData(kem->length_shared_secret, '\0');

    // Retrieve the public and private keys to decrypt
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("DecryptCommand", "Failed to retrieve key pair for decryption.");
        OQS_KEM_free(kem);
        return false;
    }

    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(&decryptedData[0]), reinterpret_cast<const uint8_t*>(encryptedCommand.data()), reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptCommand", "Failed to decapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    // Placeholder: convert decrypted data back to command name and parameters
    std::istringstream iss(decryptedData);
    if (!(iss >> commandName)) {
        errorHandler.HandleError("DecryptCommand", "Failed to parse decrypted command name.");
        OQS_KEM_free(kem);
        return false;
    }

    std::string param;
    while (iss >> param) {
        parameters.push_back(param);
    }

    OQS_KEM_free(kem);
    return true;
}
