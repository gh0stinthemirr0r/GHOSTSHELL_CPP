// command_log.h
// File Path: ghostshell/CommandLog/command_log.h

#ifndef COMMAND_LOG_H
#define COMMAND_LOG_H

#include <string>

class ErrorHandler; // Forward declaration to avoid including the entire error_handler.h here.

class CommandLog {
public:
    CommandLog();
    ~CommandLog();

    bool InitializePostQuantumEncryption();
    bool LogCommand(const std::string& command);

private:
    ErrorHandler* errorHandler; // Declare as a pointer to avoid including the full class.

    // Placeholder for encryption context if required.
};

#endif // COMMAND_LOG_H
