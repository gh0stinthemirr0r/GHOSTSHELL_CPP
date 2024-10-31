#pragma once
#ifndef GHOSTBROWSE_EXTENSIONS_MANAGER_H
#define GHOSTBROWSE_EXTENSIONS_MANAGER_H

#include <string>
#include <vector>
#include <memory>
#include <mutex>  // For thread safety
#include <unordered_map>
#include <oqs/oqs.h>  // Post-quantum cryptography library

namespace ghostbrowse {

    // A structure representing a trusted extension.
    struct TrustedExtension {
        std::string name;
        std::string path;
        std::string version;
        std::vector<uint8_t> public_key;  // Public key for signature verification
    };

    class ExtensionsManager {
    public:
        // Constructor and Destructor
        ExtensionsManager();
        ~ExtensionsManager();

        // Adds a new trusted extension to the list.
        bool add_trusted_extension(const TrustedExtension& extension, const std::vector<uint8_t>& signature);

        // Removes a trusted extension by its name.
        bool remove_trusted_extension(const std::string& extension_name);

        // Loads a trusted extension.
        bool load_trusted_extension(const std::string& extension_name);

        // Verifies the signature of an extension using OQS post-quantum algorithms.
        bool verify_extension_signature(const TrustedExtension& extension, const std::vector<uint8_t>& signature);

        // Lists all available trusted extensions.
        std::vector<TrustedExtension> list_trusted_extensions();

    private:
        // Thread-safety lock to avoid data race conditions.
        std::mutex extensions_mutex;

        // Container to hold all trusted extensions.
        std::unordered_map<std::string, TrustedExtension> trusted_extensions;

        // A helper function to load extension metadata.
        bool load_metadata(const std::string& extension_path, TrustedExtension& extension);
    };

}  // namespace ghostbrowse

#endif  // GHOSTBROWSE_EXTENSIONS_MANAGER_H
