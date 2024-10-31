// ghostauth_policy.cpp
// File Path: ghostshell/GhostAuth/ghostauth_policy.cpp
#include "ghostauth_policy.h"
#include <iostream>
#include <sstream>
#include <oqs/oqs.h>

GhostAuthPolicy::GhostAuthPolicy() {
    // Constructor implementation if needed
}

GhostAuthPolicy::~GhostAuthPolicy() {
    // Destructor implementation if needed
}

bool GhostAuthPolicy::AddPolicy(const std::string& policyName, const std::vector<std::string>& permissions) {
    if (policies.find(policyName) != policies.end()) {
        errorHandler.HandleError("AddPolicy", "Policy already exists: " + policyName);
        return false;
    }

    Policy newPolicy;
    newPolicy.permissions = permissions;
    policies[policyName] = newPolicy;

    std::cout << "[GhostAuthPolicy] Policy added successfully: " << policyName << std::endl;
    return true;
}

bool GhostAuthPolicy::RemovePolicy(const std::string& policyName) {
    auto it = policies.find(policyName);
    if (it == policies.end()) {
        errorHandler.HandleError("RemovePolicy", "Policy not found: " + policyName);
        return false;
    }

    policies.erase(it);
    std::cout << "[GhostAuthPolicy] Policy removed successfully: " << policyName << std::endl;
    return true;
}

bool GhostAuthPolicy::EditPolicy(const std::string& policyName, const std::vector<std::string>& newPermissions) {
    auto it = policies.find(policyName);
    if (it == policies.end()) {
        errorHandler.HandleError("EditPolicy", "Policy not found: " + policyName);
        return false;
    }

    it->second.permissions = newPermissions;
    std::cout << "[GhostAuthPolicy] Policy edited successfully: " << policyName << std::endl;
    return true;
}

bool GhostAuthPolicy::AssignPolicyToUser(const std::string& username, const std::string& policyName) {
    if (policies.find(policyName) == policies.end()) {
        errorHandler.HandleError("AssignPolicyToUser", "Policy not found: " + policyName);
        return false;
    }

    userPolicies[username].assignedPolicies.push_back(policyName);
    std::cout << "[GhostAuthPolicy] Policy assigned successfully to user: " << username << std::endl;
    return true;
}

bool GhostAuthPolicy::RevokePolicyFromUser(const std::string& username, const std::string& policyName) {
    auto userIt = userPolicies.find(username);
    if (userIt == userPolicies.end()) {
        errorHandler.HandleError("RevokePolicyFromUser", "User not found: " + username);
        return false;
    }

    auto& assignedPolicies = userIt->second.assignedPolicies;
    auto policyIt = std::find(assignedPolicies.begin(), assignedPolicies.end(), policyName);
    if (policyIt == assignedPolicies.end()) {
        errorHandler.HandleError("RevokePolicyFromUser", "Policy not assigned to user: " + policyName);
        return false;
    }

    assignedPolicies.erase(policyIt);
    std::cout << "[GhostAuthPolicy] Policy revoked successfully from user: " << username << std::endl;
    return true;
}

bool GhostAuthPolicy::VerifyUserPermission(const std::string& username, const std::string& permission) const {
    auto userIt = userPolicies.find(username);
    if (userIt == userPolicies.end()) {
        errorHandler.HandleError("VerifyUserPermission", "User not found: " + username);
        return false;
    }

    const auto& assignedPolicies = userIt->second.assignedPolicies;
    for (const auto& policyName : assignedPolicies) {
        auto policyIt = policies.find(policyName);
        if (policyIt != policies.end()) {
            const auto& permissions = policyIt->second.permissions;
            if (std::find(permissions.begin(), permissions.end(), permission) != permissions.end()) {
                return true;
            }
        }
    }

    errorHandler.HandleError("VerifyUserPermission", "Permission not found for user: " + username);
    return false;
}

bool GhostAuthPolicy::EncryptPolicyData(const std::string& data, std::string& encryptedData) const {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("EncryptPolicyData", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string publicKey(kem->length_public_key, '\0');
    std::string sharedSecret(kem->length_shared_secret, '\0');
    encryptedData.resize(kem->length_ciphertext);

    if (OQS_KEM_keypair(kem, (uint8_t*)publicKey.data(), (uint8_t*)encryptedData.data()) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptPolicyData", "Failed to generate encryption key pair.");
        OQS_KEM_free(kem);
        return false;
    }

    if (OQS_KEM_encaps(kem, (uint8_t*)encryptedData.data(), (uint8_t*)sharedSecret.data(), (uint8_t*)publicKey.data()) != OQS_SUCCESS) {
        errorHandler.HandleError("EncryptPolicyData", "Failed to encapsulate policy data.");
        OQS_KEM_free(kem);
        return false;
    }

    encryptedData = sharedSecret; // Placeholder for encrypted content
    OQS_KEM_free(kem);
    return true;
}

bool GhostAuthPolicy::DecryptPolicyData(const std::string& encryptedData, std::string& decryptedData) const {
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (kem == nullptr) {
        errorHandler.HandleError("DecryptPolicyData", "Failed to initialize quantum-safe key encapsulation mechanism.");
        return false;
    }

    std::string privateKey(kem->length_secret_key, '\0');
    decryptedData.resize(kem->length_shared_secret);

    if (OQS_KEM_keypair(kem, (uint8_t*)privateKey.data(), (uint8_t*)encryptedData.data()) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptPolicyData", "Failed to retrieve decryption key pair.");
        OQS_KEM_free(kem);
        return false;
    }

    if (OQS_KEM_decaps(kem, (uint8_t*)decryptedData.data(), (const uint8_t*)encryptedData.data(), (const uint8_t*)privateKey.data()) != OQS_SUCCESS) {
        errorHandler.HandleError("DecryptPolicyData", "Failed to decapsulate policy data.");
        OQS_KEM_free(kem);
        return false;
    }

    OQS_KEM_free(kem);
    return true;
}
