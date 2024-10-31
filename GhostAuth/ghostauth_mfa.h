// ghostauth_mfa.h - Post-Quantum Edition
#ifndef GHOSTAUTH_MFA_H
#define GHOSTAUTH_MFA_H

#include <string>
#include <map>
#include <mutex>
#include <ctime>
#include "error_handler.h"
#include <oqs/oqs.h>

class GhostAuthMFA {
public:
    GhostAuthMFA();
    ~GhostAuthMFA();

    // Enables MFA for a given username
    bool EnableMFA(const std::string& username);
    // Disables MFA for a given username
    bool DisableMFA(const std::string& username);
    // Generates an MFA token for the given username
    bool GenerateMFAToken(const std::string& username, std::string& token);
    // Verifies if the provided MFA token is valid for the given username
    bool VerifyMFAToken(const std::string& username, const std::string& token) const;

private:
    struct UserMFA {
        bool mfaEnabled = false;           // MFA status for the user
        std::string mfaToken;              // The generated MFA token
        std::time_t tokenExpiry;           // Token expiry timestamp
    };

    std::map<std::string, UserMFA> userMFA; // A map storing MFA details for each user
    mutable std::mutex mfaMutex;            // Mutex to ensure thread safety during MFA operations

    ErrorHandler errorHandler;              // Instance to handle errors consistently

    // Generates a post-quantum secure token using quantum-safe key encapsulation
    bool QuantumSafeGenerateToken(std::string& token);
    // Checks whether the provided MFA token is valid for the given user's MFA configuration
    bool IsMFATokenValid(const UserMFA& userMFA, const std::string& token) const;
};

#endif // GHOSTAUTH_MFA_H
