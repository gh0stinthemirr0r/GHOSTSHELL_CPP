#pragma once
// ghostvault.h - Post-Quantum Edition
// File Path: ghostshell/GhostVault/ghostvault.h

#ifndef GHOSTVAULT_H
#define GHOSTVAULT_H

#include <string>
#include <map>
#include <mutex>
#include "error_handler.h" // Ensure the full definition of ErrorHandler is included
#include <oqs/oqs.h>       // Quantum-safe operations

class GhostVault {
public:
    GhostVault();
    ~GhostVault();

    /**
     * Stores a secret securely in the vault.
     * @param key The key used to store the secret.
     * @param value The value to be stored, encrypted in the vault.
     * @return True if the secret was successfully stored, otherwise False.
     */
    bool StoreSecret(const std::string& key, const std::string& value);

    /**
     * Retrieves a secret from the vault.
     * @param key The key of the secret to be retrieved.
     * @param value The decrypted value retrieved from the vault.
     * @return True if the secret was successfully retrieved, otherwise False.
     */
    bool RetrieveSecret(const std::string& key, std::string& value);

    /**
     * Deletes a secret from the vault.
     * @param key The key of the secret to be deleted.
     * @return True if the secret was successfully deleted, otherwise False.
     */
    bool DeleteSecret(const std::string& key);

    /**
     * Generates a quantum-safe key pair for use in the vault.
     * @param generatedPublicKey The generated public key.
     * @param generatedPrivateKey The generated private key.
     * @return True if the key pair was successfully generated, otherwise False.
     */
    bool GenerateVaultKeyPair(std::string& generatedPublicKey, std::string& generatedPrivateKey);

private:
    /**
     * Encrypts data using a quantum-safe key encapsulation mechanism.
     * @param data The plaintext data to be encrypted.
     * @param encryptedData The output encrypted data.
     * @param publicKey The public key used for encryption.
     * @return True if the data was successfully encrypted, otherwise False.
     */
    bool EncryptData(const std::string& data, std::string& encryptedData, const std::string& publicKey);

    /**
     * Decrypts data using a quantum-safe key encapsulation mechanism.
     * @param encryptedData The encrypted data to be decrypted.
     * @param decryptedData The output decrypted data.
     * @param privateKey The private key used for decryption.
     * @return True if the data was successfully decrypted, otherwise False.
     */
    bool DecryptData(const std::string& encryptedData, std::string& decryptedData, const std::string& privateKey);

    /**
     * Initializes a quantum-safe key encapsulation mechanism (KEM).
     * @param kem A pointer to the KEM mechanism to be initialized.
     * @return True if the KEM was successfully initialized, otherwise False.
     */
    bool InitializePostQuantumKEM(OQS_KEM** kem);

    // Variables for storing keys and secrets
    std::string publicKey;    // The quantum-safe public key used for encryption
    std::string privateKey;   // The quantum-safe private key used for decryption
    std::map<std::string, std::string> secrets; // Encrypted secrets stored in the vault

    // Mutex for thread safety
    std::mutex vaultMutex;

    // Error handling instance
    ErrorHandler errorHandler; // Handles errors throughout the vault operations
};

#endif // GHOSTVAULT_H
