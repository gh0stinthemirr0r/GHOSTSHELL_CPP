// network_manager.h
// File Path: ghostshell/ghostnet/network_manager.h
#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <string>
#include <vector>
#include <map>
#include <mutex>
#include "error_handler.h"
#include "crypto_manager.h"  // Changed to use CryptoManager instead of GhostVault
#include <oqs/oqs.h>

class NetworkManager {
public:
    NetworkManager();
    ~NetworkManager();

    // Retrieve network configurations
    bool GetNetworkConfiguration(std::string& configOutput);

    // Ping a given network address and encrypt the result
    bool PingAddress(const std::string& address, std::string& pingResult);

    // Quantum-safe key pair generation
    bool GenerateQuantumSafeKeyPair(std::string& publicKey, std::string& privateKey);

private:
    ErrorHandler errorHandler;
    CryptoManager cryptoManager;

    // Quantum-safe encryption for network data
    bool EncryptNetworkData(const std::string& data, std::string& encryptedData, const std::string& publicKey) const;
    bool DecryptNetworkData(const std::string& encryptedData, std::string& decryptedData, const std::string& privateKey) const;

    std::mutex networkMutex;
};

#endif // NETWORK_MANAGER_H
