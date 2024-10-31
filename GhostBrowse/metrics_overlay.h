#ifndef GHOSTSHELL_METRICS_OVERLAY_H
#define GHOSTSHELL_METRICS_OVERLAY_H

#include <oqs/oqs.h>
#include <string>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include "ghostvault.h" // Ensures access to the GhostShell Vault for secure storage

namespace ghostshell {

    class MetricsOverlay {
    public:
        // Constructor and Destructor
        MetricsOverlay();
        ~MetricsOverlay();

        // Metrics collection initiation
        bool initialize_metrics();

        // Periodic update of network metrics
        void update_metrics();

        // Retrieve current metrics for displaying
        std::map<std::string, std::string> get_metrics() const;

        // Post-Quantum Secure Verification of Extension's Authenticity
        bool verify_extension_signature(const std::string& extension_name, const std::vector<uint8_t>& signature);

        // Set metrics refresh rate (in milliseconds)
        void set_refresh_rate(uint32_t rate);

    private:
        // Internal methods for collecting individual metrics
        void collect_network_latency();
        void collect_packet_loss();
        void collect_network_throughput();

        // Helper function for generating secure metrics report
        std::string generate_metrics_report() const;

        // OQS-KEM keypair generation for secure transmission
        bool generate_post_quantum_keypair();

        // Private member variables
        mutable std::mutex metrics_mutex_; // Protects metrics map for multi-threaded access
        std::map<std::string, std::string> network_metrics_; // Holds current network metrics
        uint32_t refresh_rate_; // Metrics refresh rate in milliseconds

        // OQS objects for keypair handling
        std::unique_ptr<OQS_KEM> kem_algorithm_;
        std::vector<uint8_t> public_key_;
        std::vector<uint8_t> private_key_;
    };

} // namespace ghostshell

#endif // GHOSTSHELL_METRICS_OVERLAY_H
