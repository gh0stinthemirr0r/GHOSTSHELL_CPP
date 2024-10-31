// command_queue.h
// File Path: ghostshell/CommandRouter/command_queue.h
#ifndef COMMAND_QUEUE_H
#define COMMAND_QUEUE_H

#include <queue>
#include <mutex>
#include <condition_variable>
#include <functional>
#include <oqs/oqs.h>
#include "error_handler.h"
#include "ghostvault.h"

class CommandQueue {
public:
    CommandQueue();
    ~CommandQueue();

    // Add a command to the queue with encryption
    bool Enqueue(const std::function<void()>& command);

    // Get the next command from the queue (blocking call) with decryption
    bool Dequeue(std::function<void()>& command);

private:
    std::queue<std::string> encryptedQueue;
    std::mutex mutex;
    std::condition_variable condVar;
    ErrorHandler errorHandler;
    GhostVault ghostVault;

    // Helper methods for encryption and decryption
    bool EncryptCommand(const std::function<void()>& command, std::string& encryptedCommand);
    bool DecryptCommand(const std::string& encryptedCommand, std::function<void()>& command);
};

#endif // COMMAND_QUEUE_H
