#include "browser_ui.h"
#include "vulkan_renderer.h"
#include "ghostbrowse_core.h"
#include <iostream>

namespace ghostbrowse {

    GhostBrowseUI::GhostBrowseUI(std::shared_ptr<GhostBrowseCore> core) : core_(core) {
        // Initialize Vulkan renderer for UI components
        vulkan_renderer_ = std::make_unique<VulkanRenderer>();
        if (!vulkan_renderer_->initialize()) {
            throw std::runtime_error("[Error] Failed to initialize Vulkan renderer.");
        }
    }

    GhostBrowseUI::~GhostBrowseUI() {
        // Shutdown Vulkan renderer and clean up resources
        vulkan_renderer_->shutdown();
    }

    void GhostBrowseUI::launchUI() {
        std::cout << "[GhostBrowseUI] Launching UI..." << std::endl;

        // Main UI loop - integrate with Vulkan renderer
        while (true) {
            vulkan_renderer_->renderFrame();
            // Handle user interaction and rendering commands
        }
    }

    void GhostBrowseUI::renderPage(const std::string& pageContent) {
        // Render the web page content using Vulkan
        vulkan_renderer_->displayPageContent(pageContent);
    }

} // namespace ghostbrowse
