#ifndef GHOSTAUTH_SESSION_H
#define GHOSTAUTH_SESSION_H

#include <string>
#include <oqs/oqs.h> // Including OQS for post-quantum security throughout the entire product
#include <map>
#include <mutex>
#include "ghostauth.h"
#include "ghostvault.h"
#include "error_handler.h"

class GhostAuthSession {
public:
    GhostAuthSession();
    ~GhostAuthSession();

    bool StartSession(const std::string& username, const std::string& signature);
    bool EndSession(const std::string& username);
    bool VerifySession(const std::string& sessionToken);
    std::string GenerateSessionToken(const std::string& username);

private:
    struct Session {
        std::string sessionToken;
        std::string publicKey;
        bool isActive;
    };

    std::map<std::string, Session> activeSessions;
    std::mutex sessionMutex;
    ErrorHandler errorHandler;

    bool GenerateQuantumSafeKeyPair(std::string& publicKey, std::string& privateKey);
    bool VerifyQuantumSafeSignature(const std::string& publicKey, const std::string& message, const std::string& signature);
};

#endif // GHOSTAUTH_SESSION_H
