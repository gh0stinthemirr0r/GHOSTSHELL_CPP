// ghostprofile.h
// File Path: ghostshell/GhostProfile/ghostprofile.h

#ifndef GHOSTPROFILE_H
#define GHOSTPROFILE_H

#include <string>
#include <unordered_map>
#include <mutex>
#include "error_handler.h"
#include <oqs/oqs.h>

class GhostProfile {
public:
    struct Profile {
        std::string publicKey;
        std::string privateKey;
    };

    GhostProfile();
    ~GhostProfile();

    bool CreateProfile(const std::string& username, const std::string& publicKey);
    bool DeleteProfile(const std::string& username);
    bool EditProfile(const std::string& profileName, const std::string& newPublicKey);
    bool RetrieveProfilePublicKey(const std::string& profileName, std::string& publicKey);
    bool EncryptProfileData(const std::string& profileName, const std::string& plaintext, std::string& encryptedData);
    bool DecryptProfileData(const std::string& profileName, const std::string& encryptedData, std::string& plaintext);

private:
    std::unordered_map<std::string, Profile> profiles;
    std::mutex profileMutex;
    ErrorHandler errorHandler;

    bool GenerateKeyPair(Profile& profile);
};

#endif // GHOSTPROFILE_H
