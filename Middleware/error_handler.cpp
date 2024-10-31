// error_handler.cpp
#include "error_handler.h"
#include <iostream>

void ErrorHandler::HandleError(const std::string& functionName, const std::string& errorMessage) {
    std::cerr << "[Error] Function: " << functionName << " - " << errorMessage << std::endl;
}
