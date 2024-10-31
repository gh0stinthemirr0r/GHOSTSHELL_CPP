#include "crypto_utils.h"
#include <oqs/oqs.h>
#include <vector>
#include <iostream>
#include <stdexcept>
#include <cstring>

namespace ghost {

    // Constructor to initialize the crypto context
    CryptoUtils::CryptoUtils() {
        if (OQS_SUCCESS != OQS_init()) {
            throw std::runtime_error("Failed to initialize OQS library");
        }
    }

    // Destructor to clean up the crypto context
    CryptoUtils::~CryptoUtils() {
        OQS_destroy();
    }

    // Method for generating a post-quantum keypair
    std::pair<std::vector<uint8_t>, std::vector<uint8_t>> CryptoUtils::generateKeyPair(const std::string& alg) {
        OQS_SIG* sig = OQS_SIG_new(alg.c_str());
        if (sig == nullptr) {
            throw std::invalid_argument("Unsupported signature algorithm: " + alg);
        }

        std::vector<uint8_t> publicKey(sig->length_public_key);
        std::vector<uint8_t> secretKey(sig->length_secret_key);

        if (OQS_SUCCESS != OQS_SIG_keypair(sig, publicKey.data(), secretKey.data())) {
            OQS_SIG_free(sig);
            throw std::runtime_error("Failed to generate keypair for algorithm: " + alg);
        }

        OQS_SIG_free(sig);
        return std::make_pair(publicKey, secretKey);
    }

    // Method for signing a message with the secret key
    std::vector<uint8_t> CryptoUtils::signMessage(const std::vector<uint8_t>& message, const std::vector<uint8_t>& secretKey, const std::string& alg) {
        OQS_SIG* sig = OQS_SIG_new(alg.c_str());
        if (sig == nullptr) {
            throw std::invalid_argument("Unsupported signature algorithm: " + alg);
        }

        size_t signature_len = sig->length_signature;
        std::vector<uint8_t> signature(signature_len);

        if (OQS_SUCCESS != OQS_SIG_sign(sig, signature.data(), &signature_len, message.data(), message.size(), secretKey.data())) {
            OQS_SIG_free(sig);
            throw std::runtime_error("Failed to sign message with algorithm: " + alg);
        }

        signature.resize(signature_len);  // Resize signature to the actual length
        OQS_SIG_free(sig);
        return signature;
    }

    // Method for verifying a message signature with the public key
    bool CryptoUtils::verifySignature(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& publicKey, const std::string& alg) {
        OQS_SIG* sig = OQS_SIG_new(alg.c_str());
        if (sig == nullptr) {
            throw std::invalid_argument("Unsupported signature algorithm: " + alg);
        }

        bool result = false;
        if (OQS_SUCCESS == OQS_SIG_verify(sig, message.data(), message.size(), signature.data(), signature.size(), publicKey.data())) {
            result = true;
        }

        OQS_SIG_free(sig);
        return result;
    }

    // Utility method for securely wiping sensitive data
    void CryptoUtils::secureWipe(uint8_t* data, size_t size) {
        if (data != nullptr) {
            std::memset(data, 0, size);
            // Adding compiler barrier to prevent optimization
            asm volatile("" : : "r"(data) : "memory");
        }
    }

} // namespace ghost
