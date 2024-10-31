#ifndef GHOSTBROWSE_UI_H
#define GHOSTBROWSE_UI_H

#include <memory>
#include <string>

namespace ghostbrowse {

    class GhostBrowseCore;
    class VulkanRenderer;

    class GhostBrowseUI {
    public:
        // Constructor takes a shared pointer to GhostBrowseCore
        GhostBrowseUI(std::shared_ptr<GhostBrowseCore> core);

        // Destructor
        ~GhostBrowseUI();

        // Launch the main UI loop
        void launchUI();

        // Render a web page
        void renderPage(const std::string& pageContent);

    private:
        std::shared_ptr<GhostBrowseCore> core_;   // Core logic for GhostBrowse
        std::unique_ptr<VulkanRenderer> vulkan_renderer_;  // Vulkan renderer for UI components
    };

} // namespace ghostbrowse

#endif // GHOSTBROWSE_UI_H
