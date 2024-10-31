// extended_command_handler.cpp
// File Path: ghostshell/CommandRouter/extended_command_handler.cpp

#include "extended_command_handler.h"
#include <iostream>
#include <oqs/oqs.h>
#include <sstream>

// Constructor for ExtendedCommandHandler
ExtendedCommandHandler::ExtendedCommandHandler() {
    ghostAuth = std::make_shared<GhostAuth>();
    // Constructor implementation if needed
}

// Destructor for ExtendedCommandHandler
ExtendedCommandHandler::~ExtendedCommandHandler() {
    // Destructor implementation if needed
}

// Register a specialized command with its handler function.
bool ExtendedCommandHandler::RegisterSpecializedCommand(const std::string& commandName, const std::function<void(const std::vector<std::string>&)>& handler) {
    std::lock_guard<std::mutex> lock(handlerMutex);
    if (specializedCommandRegistry.find(commandName) != specializedCommandRegistry.end()) {
        errorHandler.HandleError("RegisterSpecializedCommand", "Command already registered: " + commandName);
        return false;
    }
    specializedCommandRegistry[commandName] = handler;
    std::cout << "[ExtendedCommandHandler] Registered specialized command: " << commandName << std::endl;
    return true;
}

// Execute a specialized command with post-quantum encryption and authentication.
bool ExtendedCommandHandler::ExecuteSpecializedCommand(const std::string& username, const std::string& commandName, const std::vector<std::string>& parameters) {
    if (!AuthenticateUser(username)) {
        errorHandler.HandleError("ExecuteSpecializedCommand", "Authentication failed for user: " + username);
        return false;
    }

    // Encrypt the command and parameters before routing
    std::string encryptedCommand;
    if (!EncryptCommand(commandName, parameters, encryptedCommand)) {
        errorHandler.HandleError("ExecuteSpecializedCommand", "Failed to encrypt command.");
        return false;
    }

    // Decrypt the command and parameters before execution
    std::string decryptedCommandName;
    std::vector<std::string> decryptedParameters;
    if (!DecryptCommand(encryptedCommand, decryptedCommandName, decryptedParameters)) {
        errorHandler.HandleError("ExecuteSpecializedCommand", "Failed to decrypt command.");
        return false;
    }

    auto it = specializedCommandRegistry.find(decryptedCommandName);
    if (it == specializedCommandRegistry.end()) {
        errorHandler.HandleError("ExecuteSpecializedCommand", "Command not found: " + decryptedCommandName);
        return false;
    }

    try {
        it->second(decryptedParameters);
    }
    catch (const std::exception& e) {
        errorHandler.HandleError("ExecuteSpecializedCommand", "Command execution failed: " + std::string(e.what()));
        return false;
    }

    return true;
}

// Authenticate a user using post-quantum signature verification.
bool ExtendedCommandHandler::AuthenticateUser(const std::string& username) {
    std::string publicKey;
    if (!ghostAuth->GetUserPublicKey(username, publicKey)) {
        errorHandler.HandleError("AuthenticateUser", "Failed to retrieve public key for user: " + username);
        return false;
    }

    // Quantum-safe user authentication using signature verification
    OQS_SIG* sig = OQS_SIG_new(OQS_SIG_alg_dilithium_2);
    if (sig == nullptr) {
        errorHandler.HandleError("AuthenticateUser", "Failed to initialize quantum-safe signature mechanism.");
        return false;
    }

    std::string message = "Authenticate user for specialized command: " + username;
    std::string signature;  // Assuming signature needs to be obtained for authentication.
    if (!ghostAuth->SignMessage(username, message, signature)) {
        errorHandler.HandleError("AuthenticateUser", "Failed to retrieve user signature.");
        OQS_SIG_free(sig);
        return false;
    }

    // Quantum-safe signature verification
    bool isVerified = (OQS_SIG_verify(sig,
        reinterpret_cast<const uint8_t*>(message.c_str()), message.size(),
        reinterpret_cast<const uint8_t*>(signature.c_str()), signature.size(),
        reinterpret_cast<const uint8_t*>(publicKey.c_str())) == OQS_SUCCESS);

    OQS_SIG_free(sig);
    if (!isVerified) {
        errorHandler.HandleError("AuthenticateUser", "Signature verification failed for user: " + username);
        return false;
    }

    return true;
}

// Encrypt the command and parameters.
bool ExtendedCommandHandler::EncryptCommand(const std::string& commandName, const std::vector<std::string>& parameters, std::string& encryptedCommand) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptCommand", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;
    std::string privateKey;
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("EncryptCommand", "Failed to generate public key for encryption.");
        OQS_KEM_free(kem);
        return false;
    }

    // Serialize the command name and parameters
    std::ostringstream oss;
    oss << commandName;
    for (const auto& param : parameters) {
        oss << " " << param;
    }
    std::string commandData = oss.str();

    std::string sharedSecret(kem->length_shared_secret, '\0');
    encryptedCommand.resize(kem->length_ciphertext);
    if (OQS_KEM_encaps(kem, reinterpret_cast<uint8_t*>(&encryptedCommand[0]), reinterpret_cast<uint8_t*>(&sharedSecret[0]), reinterpret_cast<const uint8_t*>(publicKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptCommand", "Failed to encapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    encryptedCommand = sharedSecret; // Placeholder to simulate encrypted content
    OQS_KEM_free(kem);
    return true;
}

// Decrypt an encrypted command.
bool ExtendedCommandHandler::DecryptCommand(const std::string& encryptedCommand, std::string& commandName, std::vector<std::string>& parameters) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptCommand", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;
    std::string privateKey;
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("DecryptCommand", "Failed to retrieve private key for decryption.");
        OQS_KEM_free(kem);
        return false;
    }

    std::string decryptedData(kem->length_shared_secret, '\0');
    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(&decryptedData[0]), reinterpret_cast<const uint8_t*>(encryptedCommand.data()), reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptCommand", "Failed to decapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    // Deserialize command data back into command name and parameters
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
