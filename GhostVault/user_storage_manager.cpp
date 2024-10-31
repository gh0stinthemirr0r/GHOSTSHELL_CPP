#include <sqlite3.h>
#include <iostream>
#include <oqs/oqs.h>
#include <string>
#include "user_storage_manager.h"

// Constructor to open the database
UserStorageManager::UserStorageManager() {
    int result = sqlite3_open("ghostshell_users.db", &db);
    if (result != SQLITE_OK) {
        std::cerr << "Cannot open database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr;
    }
}

// Destructor to close the database
UserStorageManager::~UserStorageManager() {
    if (db) {
        sqlite3_close(db);
    }
}

// Function to store encrypted user data in the database
bool UserStorageManager::StoreUserData(const std::string& username, const std::string& data) {
    if (!db) {
        return false;  // Database is not open
    }

    // Encrypt the data using a post-quantum secure method (e.g., Kyber)
    std::string encryptedData;
    if (!EncryptData(data, encryptedData)) {
        std::cerr << "Failed to encrypt data for user: " << username << std::endl;
        return false;
    }

    // Create an SQL query to insert encrypted data
    std::string sql = "INSERT INTO users (username, encrypted_data) VALUES (?, ?);";
    sqlite3_stmt* stmt;

    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
        std::cerr << "Failed to prepare statement: " << sqlite3_errmsg(db) << std::endl;
        return false;
    }

    sqlite3_bind_text(stmt, 1, username.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, encryptedData.c_str(), -1, SQLITE_STATIC);

    if (sqlite3_step(stmt) != SQLITE_DONE) {
        std::cerr << "Failed to execute statement: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_finalize(stmt);
        return false;
    }

    sqlite3_finalize(stmt);
    return true;
}

// Encrypt the data with a post-quantum secure method
bool UserStorageManager::EncryptData(const std::string& plaintext, std::string& encryptedData) {
    // Example using Kyber for encryption
    OQS_KEM* kem = OQS_KEM_new(OQS_KEM_alg_kyber_512);
    if (!kem) {
        std::cerr << "Failed to initialize Kyber KEM." << std::endl;
        return false;
    }

    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret(kem->length_shared_secret);
    std::string public_key; // Should be the receiver's public key, generated and stored securely.

    if (OQS_KEM_encaps(kem, ciphertext.data(), shared_secret.data(),
        reinterpret_cast<const uint8_t*>(public_key.data())) != OQS_SUCCESS) {
        std::cerr << "Failed to encrypt data using Kyber." << std::endl;
        OQS_KEM_free(kem);
        return false;
    }

    encryptedData.assign(ciphertext.begin(), ciphertext.end());
    OQS_KEM_free(kem);
    return true;
}
