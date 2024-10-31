// ghostauth.h - Authentication Header for GhostShell
// File Path: ghostshell/ghostauth.h

#ifndef GHOSTAUTH_H
#define GHOSTAUTH_H

#include <string>
#include <unordered_map>
#include <vector>
#include <oqs.h>
#include "user_storage_manager.h" // Include UserStorageManager

class GhostAuth {
public:
    // Constructor and Destructor for initializing and cleaning up OQS library
    GhostAuth();
    ~GhostAuth();

    // Generate a post-quantum key pair for a user
    bool GeneratePostQuantumKeyPair(std::string& publicKey, std::string& privateKey);

    // Add a user and generate a key pair for them
    bool AddUser(const std::string& username);

    // Authenticate a user based on a signature using Dilithium-2
    bool AuthenticateUser(const std::string& username, const std::string& signature);

    // Retrieve the public key for a specific user
    bool GetUserPublicKey(const std::string& username, std::string& publicKey) const;

    // Sign a message with the user's private key using Dilithium-2
    bool SignMessage(const std::string& username, const std::string& message, std::string& signature);

    // Retrieve the private key securely by verifying user authorization
    bool GetAuthorizedPrivateKey(const std::string& username, std::string& privateKey) const;

private:
    // Storage for public and private keys, mapped by username
    std::unordered_map<std::string, std::pair<std::string, std::string>> userKeys;

    // Persistent storage manager for user credentials
    UserStorageManager userStorage;
};

#endif // GHOSTAUTH_H
