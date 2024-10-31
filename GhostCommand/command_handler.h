// command_handler.h - Command Handler Header
// File Path: ghostshell/command_handler.h

#ifndef COMMAND_HANDLER_H
#define COMMAND_HANDLER_H

#include <string>

class CommandHandler {
public:
    CommandHandler();
    ~CommandHandler();

    // Function to process commands entered by the user
    bool processCommand(const std::string& command);
};

#endif // COMMAND_HANDLER_H
