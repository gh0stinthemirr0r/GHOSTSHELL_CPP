// ghostprofile.cpp
// File Path: ghostshell/GhostProfile/ghostprofile.cpp

#include "ghostprofile.h"
#include <iostream>
#include <oqs/oqs.h>
#include <sstream>

GhostProfile::GhostProfile() {
    // Constructor implementation
}

GhostProfile::~GhostProfile() {
    // Destructor implementation
}

bool GhostProfile::CreateProfile(const std::string& username, const std::string& publicKey) {
    std::lock_guard<std::mutex> lock(profileMutex);

    if (profiles.find(username) != profiles.end()) {
        errorHandler.HandleError("CreateProfile", "Profile already exists for user: " + username);
        return false;
    }

    Profile newProfile;
    newProfile.publicKey = publicKey;

    // Generate a private key for the new profile
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("CreateProfile", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }
    std::string privateKey(kem->length_secret_key, '\0');
    if (OQS_KEM_keypair(kem, reinterpret_cast<uint8_t*>(&newProfile.publicKey[0]), reinterpret_cast<uint8_t*>(&privateKey[0])) != OQS_SUCCESS) {
        errorHandler.HandleError("CreateProfile", "Failed to generate key pair for user: " + username);
        OQS_KEM_free(kem);
        return false;
    }
    newProfile.privateKey = privateKey;
    OQS_KEM_free(kem);

    profiles[username] = std::move(newProfile);

    std::cout << "[GhostProfile] Profile created successfully for user: " << username << std::endl;
    return true;
}

bool GhostProfile::DeleteProfile(const std::string& username) {
    std::lock_guard<std::mutex> lock(profileMutex);

    auto it = profiles.find(username);
    if (it == profiles.end()) {
        errorHandler.HandleError("DeleteProfile", "Profile not found for user: " + username);
        return false;
    }

    profiles.erase(it);
    std::cout << "[GhostProfile] Profile deleted for user: " << username << std::endl;
    return true;
}

bool GhostProfile::EditProfile(const std::string& profileName, const std::string& newPublicKey) {
    std::lock_guard<std::mutex> lock(profileMutex);

    auto it = profiles.find(profileName);
    if (it == profiles.end()) {
        errorHandler.HandleError("EditProfile", "Profile not found for user: " + profileName);
        return false;
    }

    it->second.publicKey = newPublicKey;
    std::cout << "[GhostProfile] Profile updated successfully for user: " << profileName << std::endl;
    return true;
}

bool GhostProfile::RetrieveProfilePublicKey(const std::string& profileName, std::string& publicKey) {
    std::lock_guard<std::mutex> lock(profileMutex);

    auto it = profiles.find(profileName);
    if (it == profiles.end()) {
        errorHandler.HandleError("RetrieveProfilePublicKey", "Profile not found for user: " + profileName);
        return false;
    }

    publicKey = it->second.publicKey;
    return true;
}

bool GhostProfile::EncryptProfileData(const std::string& profileName, const std::string& plaintext, std::string& encryptedData) {
    std::lock_guard<std::mutex> lock(profileMutex);

    auto it = profiles.find(profileName);
    if (it == profiles.end()) {
        errorHandler.HandleError("EncryptProfileData", "Profile not found for user: " + profileName);
        return false;
    }

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptProfileData", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    const std::string& publicKey = it->second.publicKey;
    encryptedData.resize(kem->length_ciphertext);
    std::string sharedSecret(kem->length_shared_secret, '\0');

    if (OQS_KEM_encaps(kem, reinterpret_cast<uint8_t*>(&encryptedData[0]), reinterpret_cast<uint8_t*>(&sharedSecret[0]), reinterpret_cast<const uint8_t*>(publicKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptProfileData", "Failed to encapsulate shared secret for user: " + profileName);
        OQS_KEM_free(kem);
        return false;
    }

    OQS_KEM_free(kem);
    return true;
}

bool GhostProfile::DecryptProfileData(const std::string& profileName, const std::string& encryptedData, std::string& plaintext) {
    std::lock_guard<std::mutex> lock(profileMutex);

    auto it = profiles.find(profileName);
    if (it == profiles.end()) {
        errorHandler.HandleError("DecryptProfileData", "Profile not found for user: " + profileName);
        return false;
    }

    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptProfileData", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    const std::string& privateKey = it->second.privateKey;
    plaintext.resize(kem->length_shared_secret);

    if (OQS_KEM_decaps(kem, reinterpret_cast<uint8_t*>(&plaintext[0]), reinterpret_cast<const uint8_t*>(encryptedData.data()), reinterpret_cast<const uint8_t*>(privateKey.data())) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptProfileData", "Failed to decapsulate shared secret for user: " + profileName);
        OQS_KEM_free(kem);
        return false;
    }

    OQS_KEM_free(kem);
    return true;
}
