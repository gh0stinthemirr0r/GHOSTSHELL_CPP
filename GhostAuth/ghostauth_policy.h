#pragma once
// ghostauth_policy.h
// File Path: ghostshell/GhostAuth/ghostauth_policy.h
#ifndef GHOSTAUTH_POLICY_H
#define GHOSTAUTH_POLICY_H

#include <string>
#include <map>
#include <vector>
#include "error_handler.h"
#include <oqs/oqs.h>

class GhostAuthPolicy {
public:
    GhostAuthPolicy();
    ~GhostAuthPolicy();

    bool AddPolicy(const std::string& policyName, const std::vector<std::string>& permissions);
    bool RemovePolicy(const std::string& policyName);
    bool EditPolicy(const std::string& policyName, const std::vector<std::string>& newPermissions);
    bool AssignPolicyToUser(const std::string& username, const std::string& policyName);
    bool RevokePolicyFromUser(const std::string& username, const std::string& policyName);
    bool VerifyUserPermission(const std::string& username, const std::string& permission) const;

    bool EncryptPolicyData(const std::string& data, std::string& encryptedData) const;
    bool DecryptPolicyData(const std::string& encryptedData, std::string& decryptedData) const;

private:
    struct Policy {
        std::vector<std::string> permissions;
    };

    struct UserPolicy {
        std::vector<std::string> assignedPolicies;
    };

    std::map<std::string, Policy> policies;
    std::map<std::string, UserPolicy> userPolicies;
    mutable ErrorHandler errorHandler; // Allows modification even in const functions
};

#endif // GHOSTAUTH_POLICY_H
