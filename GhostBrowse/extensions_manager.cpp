#include "extensions_manager.h"
#include "ghostvault.h"
#include <oqs/oqs.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <mutex> // for thread safety
#include <memory>
#include <filesystem>

namespace ghostshell {

    namespace fs = std::filesystem;

    std::mutex extension_mutex;

    ExtensionsManager::ExtensionsManager() {
        std::cout << "[GhostExtensions] Initializing Extensions Manager with post-quantum security." << std::endl;
    }

    ExtensionsManager::~ExtensionsManager() {
        std::cout << "[GhostExtensions] Cleaning up Extensions Manager." << std::endl;
    }

    void ExtensionsManager::load_trusted_extensions(const std::string& extensions_dir) {
        std::lock_guard<std::mutex> lock(extension_mutex);

        std::cout << "[GhostExtensions] Loading trusted extensions from: " << extensions_dir << std::endl;

        try {
            if (!fs::exists(extensions_dir)) {
                throw std::runtime_error("Directory does not exist: " + extensions_dir);
            }

            for (const auto& entry : fs::directory_iterator(extensions_dir)) {
                if (entry.is_regular_file() && entry.path().extension() == ".ext") {
                    std::string file_content;
                    std::ifstream file(entry.path());
                    if (file) {
                        std::ostringstream ss;
                        ss << file.rdbuf();
                        file_content = ss.str();

                        if (verify_extension_signature(file_content)) {
                            std::cout << "[GhostExtensions] Extension " << entry.path().filename() << " is verified and loaded." << std::endl;
                            loaded_extensions.push_back(entry.path().filename().string());
                        }
                        else {
                            std::cout << "[GhostExtensions] Warning: Extension " << entry.path().filename() << " failed verification." << std::endl;
                        }
                    }
                }
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[GhostExtensions] Error loading extensions: " << e.what() << std::endl;
        }
    }

    bool ExtensionsManager::verify_extension_signature(const std::string& extension_content) {
        std::lock_guard<std::mutex> lock(extension_mutex);

        std::cout << "[GhostExtensions] Verifying extension signature." << std::endl;

        // OQS_SIG: instantiate the OQS signature mechanism.
        std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> sig(OQS_SIG_new(OQS_SIG_alg_dilithium_3), OQS_SIG_free);
        if (sig == nullptr) {
            std::cerr << "[GhostExtensions] Failed to initialize post-quantum signature scheme." << std::endl;
            return false;
        }

        // Placeholder public key and signature - in a real-world scenario these would come from a trusted source.
        const uint8_t public_key[OQS_SIG_dilithium_3_length_public_key] = { 0 };
        const uint8_t signature[OQS_SIG_dilithium_3_length_signature] = { 0 };
        size_t signature_len = sizeof(signature);

        // Verify the signature of the extension content.
        OQS_STATUS status = OQS_SIG_verify(sig.get(), (const uint8_t*)extension_content.c_str(), extension_content.length(), signature, signature_len, public_key);
        if (status == OQS_SUCCESS) {
            std::cout << "[GhostExtensions] Signature verified successfully." << std::endl;
            return true;
        }
        else {
            std::cout << "[GhostExtensions] Signature verification failed." << std::endl;
            return false;
        }
    }

    bool ExtensionsManager::add_extension(const std::string& extension_path) {
        std::lock_guard<std::mutex> lock(extension_mutex);

        std::cout << "[GhostExtensions] Adding extension from path: " << extension_path << std::endl;

        try {
            if (!fs::exists(extension_path) || fs::path(extension_path).extension() != ".ext") {
                throw std::runtime_error("Invalid extension file: " + extension_path);
            }

            std::string file_content;
            std::ifstream file(extension_path);
            if (file) {
                std::ostringstream ss;
                ss << file.rdbuf();
                file_content = ss.str();

                if (verify_extension_signature(file_content)) {
                    loaded_extensions.push_back(fs::path(extension_path).filename().string());
                    std::cout << "[GhostExtensions] Extension " << fs::path(extension_path).filename() << " successfully added." << std::endl;
                    return true;
                }
                else {
                    std::cout << "[GhostExtensions] Failed to add extension. Signature verification failed." << std::endl;
                }
            }
            else {
                throw std::runtime_error("Failed to open extension file: " + extension_path);
            }
        }
        catch (const std::exception& e) {
            std::cerr << "[GhostExtensions] Error adding extension: " << e.what() << std::endl;
        }

        return false;
    }

    void ExtensionsManager::list_extensions() const {
        std::lock_guard<std::mutex> lock(extension_mutex);

        std::cout << "[GhostExtensions] Listing loaded extensions:" << std::endl;
        for (const auto& ext : loaded_extensions) {
            std::cout << " - " << ext << std::endl;
        }
    }

} // namespace ghostshell
