#include <sqlite3.h>
#include "user_storage_manager.h"
#include <iostream>

UserStorageManager::UserStorageManager() {
    // Attempt to open the database file
    int result = sqlite3_open("ghostshell_users.db", &db);
    if (result != SQLITE_OK) {
        std::cerr << "Failed to open the SQLite database: " << sqlite3_errmsg(db) << std::endl;
        sqlite3_close(db);
        db = nullptr; // Set db to nullptr since it's not successfully opened
    }
}

UserStorageManager::~UserStorageManager() {
    if (db) {
        sqlite3_close(db);
    }
}
