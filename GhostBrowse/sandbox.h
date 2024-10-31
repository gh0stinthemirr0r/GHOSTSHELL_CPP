#pragma once
#ifndef GHOSTSHELL_SANDBOX_H
#define GHOSTSHELL_SANDBOX_H

#include <oqs/oqs.h>
#include <string>
#include <memory>
#include <mutex>
#include "ghostvault.h"

namespace ghostshell {

    class Sandbox {
    public:
        // Constructor & Destructor
        Sandbox();
        ~Sandbox();

        // Initialize the sandbox environment
        void initialize();

        // Cleanup resources safely
        void cleanup();

        // Run secure command within sandbox
        bool runCommand(const std::string& command, std::string& result);

        // Generate and verify signatures using post-quantum cryptographic methods
        bool generateSignature(const std::string& message, std::vector<uint8_t>& signature);
        bool verifySignature(const std::string& message, const std::vector<uint8_t>& signature);

    private:
        // OQS signature context
        std::unique_ptr<OQS_SIG> oqs_sig;
        std::unique_ptr<OQS_SIG> oqs_verify_sig;
        std::mutex sandbox_mutex;

        // Secure environment setup
        bool setupPostQuantumTLS();

        // Helper to configure internal sandboxing mechanisms
        void configureSandboxEnvironment();

        // Helper to execute command securely
        bool executeCommand(const std::string& command, std::string& output);
    };

} // namespace ghostshell

#endif // GHOSTSHELL_SANDBOX_H
    