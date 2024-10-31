// command_queue.cpp
// File Path: ghostshell/CommandRouter/command_queue.cpp
#include "command_queue.h"
#include <sstream>

CommandQueue::CommandQueue() {
    // Constructor implementation if needed
}

CommandQueue::~CommandQueue() {
    // Destructor implementation if needed
}

bool CommandQueue::Enqueue(const std::function<void()>& command) {
    std::string encryptedCommand;
    if (!EncryptCommand(command, encryptedCommand)) {
        errorHandler.HandleError("Enqueue", "Failed to encrypt command.");
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(mutex);
        encryptedQueue.push(encryptedCommand);
    }
    condVar.notify_one();
    return true;
}

bool CommandQueue::Dequeue(std::function<void()>& command) {
    std::unique_lock<std::mutex> lock(mutex);
    condVar.wait(lock, [this] { return !encryptedQueue.empty(); });
    std::string encryptedCommand = encryptedQueue.front();
    encryptedQueue.pop();

    if (!DecryptCommand(encryptedCommand, command)) {
        errorHandler.HandleError("Dequeue", "Failed to decrypt command.");
        return false;
    }

    return true;
}

bool CommandQueue::EncryptCommand(const std::function<void()>& command, std::string& encryptedCommand) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptCommand", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    // Make sure to use mutable strings for both public and private keys
    std::string publicKey;
    std::string privateKey;

    // Correct usage of `GenerateVaultKeyPair` to use non-const references
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("EncryptCommand", "Failed to generate key pair for encryption.");
        OQS_KEM_free(kem);
        return false;
    }

    // Serialize the command (as a placeholder, using command pointer address as a dummy string)
    std::ostringstream oss;
    oss << &command;
    std::string commandData = oss.str();

    std::string sharedSecret(kem->length_shared_secret, '\0');
    encryptedCommand.resize(kem->length_ciphertext);

    if (OQS_KEM_encaps(kem, reinterpret_cast<uint8_t*>(&encryptedCommand[0]), reinterpret_cast<uint8_t*>(&sharedSecret[0]), reinterpret_cast<const uint8_t*>(publicKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptCommand", "Failed to encapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    encryptedCommand = sharedSecret; // Placeholder to simulate the encrypted content
    OQS_KEM_free(kem);
    return true;
}

bool CommandQueue::DecryptCommand(const std::string& encryptedCommand, std::function<void()>& command) {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptCommand", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey;
    std::string privateKey;

    // Correct usage of `GenerateVaultKeyPair` to use non-const references
    if (!ghostVault.GenerateVaultKeyPair(publicKey, privateKey)) {
        errorHandler.HandleError("DecryptCommand", "Failed to retrieve key pair for decryption.");
        OQS_KEM_free(kem);
        return false;
    }

    std::string decryptedData(kem->length_shared_secret, '\0');
    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(&decryptedData[0]), reinterpret_cast<const uint8_t*>(encryptedCommand.data()), reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptCommand", "Failed to decapsulate shared secret.");
        OQS_KEM_free(kem);
        return false;
    }

    // Placeholder: convert decrypted data back to command (for now, just a dummy function pointer)
    command = []() { /* dummy command */ };

    OQS_KEM_free(kem);
    return true;
}
