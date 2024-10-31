// error_handler.h
#ifndef ERROR_HANDLER_H
#define ERROR_HANDLER_H

#include <string>

class ErrorHandler {
public:
    ErrorHandler() = default;
    ~ErrorHandler() = default;

    void HandleError(const std::string& functionName, const std::string& errorMessage);
};

#endif // ERROR_HANDLER_H
