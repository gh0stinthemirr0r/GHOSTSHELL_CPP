#ifndef GHOSTAUTH_MANAGER_H
#define GHOSTAUTH_MANAGER_H

#include "ghostauth.h"
#include "ghostvault.h"
#include "error_handler.h"
#include <string>
#include <unordered_map>
#include <vector>

struct UserSession {
    std::string sessionToken;
    GhostVault* vault;
};

class GhostAuthManager {
public:
    GhostAuthManager(GhostAuth& authRef);
    ~GhostAuthManager();

    bool StartUserSession(const std::string& username, const std::string& signature);
    bool EndUserSession(const std::string& username);
    bool RegisterUser(const std::string& username);
    bool RemoveUser(const std::string& username);
    bool EditUser(const std::string& username, const std::string& newUsername);
    GhostVault* GetUserVault(const std::string& username);
    bool EnableMFA(const std::string& username);
    bool VerifyMFAToken(const std::string& username, const std::string& token);
    bool GenerateSessionToken(const std::string& username, std::string& sessionToken);
    bool GenerateMFAToken(const std::string& username, std::string& token);
    bool VerifyQuantumSafeSignature(const std::string& username, const std::string& message, const std::string& signature) const;

private:
    GhostAuth& ghostAuth;
    ErrorHandler errorHandler;
    std::unordered_map<std::string, UserSession> activeSessions;
};

bool VerifyMFAToken(const std::string& token);
bool IsMFATokenValid(const std::string& token);


#endif // GHOSTAUTH_MANAGER_H
