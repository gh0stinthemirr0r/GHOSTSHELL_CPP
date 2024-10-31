#ifndef GHOSTSHELL_BROWSER_CORE_H
#define GHOSTSHELL_BROWSER_CORE_H

#include <memory>
#include <string>

// Forward declarations for all the classes used
class Sandbox;
class PQTLS;
class NetworkStack;
class GhostVPN;
class ExtensionsManager;

namespace ghostbrowse {

    class GhostBrowseUI; // Forward declaration of GhostBrowseUI for UI interaction

    class GhostBrowseCore {
    public:
        // Constructor and Destructor
        GhostBrowseCore();
        ~GhostBrowseCore();

        // Methods to manage browsing
        void startBrowsingSession(const std::string& url);
        void applySecurityPolicies();
        void handleUserCommand(const std::string& command);
        void run();

    private:
        // Private method to render a page
        void renderPage(const std::string& pageContent);

        // Private member variables for the core browsing components
        std::unique_ptr<Sandbox> sandbox_;
        std::unique_ptr<PQTLS> pq_tls_;
        std::unique_ptr<NetworkStack> network_stack_;
        std::unique_ptr<GhostVPN> ghostvpn_;
        std::unique_ptr<ExtensionsManager> extensions_manager_;
        std::shared_ptr<GhostBrowseUI> browser_ui_;
    };

} // namespace ghostbrowse

#endif // GHOSTSHELL_BROWSER_CORE_H
#pragma once
