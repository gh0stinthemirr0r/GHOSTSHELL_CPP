#pragma once
#ifndef NETWORK_STACK_H
#define NETWORK_STACK_H

#include <string>
#include <memory>
#include <mutex>
#include <vector>
#include <oqs/oqs.h> // For leveraging post-quantum cryptographic operations

namespace ghost {

    // NetworkAddress struct to hold IP address and other details
    struct NetworkAddress {
        std::string ip;
        int port;
    };

    class PostQuantumSecureSession {
    public:
        PostQuantumSecureSession(const std::string& localPrivateKeyPath);
        ~PostQuantumSecureSession();

        // Initializes post-quantum secure session using liboqs
        bool initializeSession(const NetworkAddress& remoteAddr);

        // Generates key exchange and returns session key
        std::vector<uint8_t> generateSessionKey();

        // Encrypt and decrypt data using the generated session key
        std::string encryptData(const std::string& data);
        std::string decryptData(const std::string& encryptedData);

        // Sends data through a secure channel
        bool sendData(const NetworkAddress& dest, const std::string& data);

        // Receives data from a secure channel
        std::string receiveData();

    private:
        std::mutex sessionMutex;  // Mutex for synchronizing access to session data
        std::unique_ptr<OQS_KEM, void(*)(OQS_KEM*)> kem; // Post-quantum key encapsulation
        std::vector<uint8_t> sessionKey; // Shared session key
        NetworkAddress remoteAddr; // Address of the remote node we're in session with

        // Utility functions for session management
        bool loadLocalPrivateKey(const std::string& path);
        void cleanupSession();
    };

    // NetworkStack class to handle different types of network connections
    class NetworkStack {
    public:
        NetworkStack();
        ~NetworkStack();

        // Initializes the network stack (including Post-Quantum configurations)
        bool initializeStack();

        // Connect to a server address
        bool connect(const NetworkAddress& address);

        // Sends data through the network stack
        bool send(const NetworkAddress& dest, const std::string& data);

        // Receives data from the network stack
        std::string receive(const NetworkAddress& source);

        // Sets up a secure session for a particular address using PostQuantumSecureSession
        bool setupSecureSession(const NetworkAddress& remoteAddr);

    private:
        std::mutex networkMutex;  // Mutex for synchronizing access to network stack
        std::vector<std::unique_ptr<PostQuantumSecureSession>> secureSessions;  // List of active secure sessions
    };

} // namespace ghost

#endif // NETWORK_STACK_H
