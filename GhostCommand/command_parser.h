// command_parser.h
// File Path: ghostshell/CommandParser/command_parser.h

#ifndef COMMAND_PARSER_H
#define COMMAND_PARSER_H

#include <string>

class ErrorHandler;  // Forward declaration to avoid direct inclusion

class CommandParser {
public:
    CommandParser();
    ~CommandParser();

    bool GenerateQuantumSafeKeyPair(std::string& publicKey, std::string& privateKey);
    bool ParseCommand(const std::string& command, std::string& parsedOutput);

private:
    ErrorHandler* errorHandler; // Declared as a pointer to avoid unnecessary dependencies.
};

#endif // COMMAND_PARSER_H
