#ifndef CRYPTO_UTILS_H
#define CRYPTO_UTILS_H

#include <oqs/oqs.h>
#include <string>
#include <vector>
#include <memory>
#include <mutex>

// Include guard for ensuring that the liboqs is initialized once
namespace ghostcrypto {

    // Thread-safe singleton OQS context manager
    class OQSContextManager {
    public:
        static OQSContextManager& getInstance();

        OQSContextManager(const OQSContextManager&) = delete;
        OQSContextManager& operator=(const OQSContextManager&) = delete;

        ~OQSContextManager();

    private:
        OQSContextManager();
        static std::mutex oqs_init_mutex;
    };

    // Key Pair Generation for Post-Quantum Algorithms
    class PQCryptoUtils {
    public:
        PQCryptoUtils(const std::string& algorithm);
        ~PQCryptoUtils();

        // Generates a key pair and returns them as a pair (public_key, secret_key)
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generateKeyPair();

        // Sign a message using the secret key, returns the signature as a vector of bytes
        std::vector<uint8_t> signMessage(const std::vector<uint8_t>& message, const std::vector<uint8_t>& secret_key);

        // Verify a signature using the public key, returns true if the verification is successful
        bool verifySignature(const std::vector<uint8_t>& message, const std::vector<uint8_t>& signature, const std::vector<uint8_t>& public_key);

        // Wipe sensitive data securely
        static void secureWipe(std::vector<uint8_t>& data);

    private:
        std::string algorithm_name;
        OQS_SIG* sig;
    };

} // namespace ghostcrypto

#endif // CRYPTO_UTILS_H
