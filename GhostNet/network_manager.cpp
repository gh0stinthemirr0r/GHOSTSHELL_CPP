// network_manager.cpp
// File Path: ghostshell/GhostNet/network_manager.cpp

#include "network_manager.h"
#include "crypto_manager.h" // Adjusted path to the correct directory for CryptoManager
#include <iostream>
#include <sstream>
#include <oqs/oqs.h>

#ifdef _WIN32
#include <windows.h>
#endif

NetworkManager::NetworkManager() {
    // Constructor implementation if needed
}

NetworkManager::~NetworkManager() {
    // Destructor implementation if needed
}

bool NetworkManager::GetNetworkConfiguration(std::string& configOutput) {
#ifdef _WIN32
    char buffer[128] = { 0 }; // Initialize the buffer to avoid uninitialized memory access.
    std::ostringstream commandOutput;
    FILE* pipe = _popen("ipconfig", "r");
    if (!pipe) {
        errorHandler.HandleError("GetNetworkConfiguration", "Failed to run ipconfig command.");
        return false;
    }
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        commandOutput << buffer;
    }
    _pclose(pipe);
    std::string rawOutput = commandOutput.str();

    // Using CryptoManager instead of GhostVault to perform encryption
    std::string publicKey, privateKey;

    // Generate key pair
    if (!cryptoManager.GenerateKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("GetNetworkConfiguration", "Failed to generate key pair for encryption.");
        return false;
    }

    // Encrypt the network configuration output using post-quantum safe Kyber
    std::string encryptedOutput;
    if (!cryptoManager.Encrypt(rawOutput, publicKey, encryptedOutput)) {
        errorHandler.HandleError("GetNetworkConfiguration", "Failed to encrypt network configuration output.");
        return false;
    }

    configOutput = encryptedOutput;
    return true;
#else
    errorHandler.HandleError("GetNetworkConfiguration", "This method is only supported on Windows.");
    return false;
#endif
}

bool NetworkManager::PingAddress(const std::string& address, std::string& pingResult) {
#ifdef _WIN32
    char buffer[128] = { 0 }; // Initialize the buffer to avoid uninitialized memory access.
    std::ostringstream commandOutput;
    std::string command = "ping " + address;
    FILE* pipe = _popen(command.c_str(), "r");
    if (!pipe) {
        errorHandler.HandleError("PingAddress", "Failed to run ping command.");
        return false;
    }
    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        commandOutput << buffer;
    }
    _pclose(pipe);
    pingResult = commandOutput.str(); // Initialize pingResult properly
    return true;
#else
    errorHandler.HandleError("PingAddress", "This method is only supported on Windows.");
    return false;
#endif
}
