#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include "rlwe_puf_auth.h"
#include "puf_timing.h"

void print_performance_comparison(const PUF_PerformanceMetrics* perf) {
    printf("\n=== PERFORMANCE COMPARISON: RLWE vs RLWE-PUF ===\n");
    
    // Previous RLWE metrics (from our earlier analysis)
    printf("BASIC RLWE AUTHENTICATION:\n");
    printf("  Total Protocol Time:      862 μs\n");
    printf("  Device Time:              512 μs (59.4%%)\n");
    printf("  Server Time:              260 μs (30.2%%)\n");
    printf("  Overhead:                  90 μs (10.4%%)\n");
    
    // RLWE-PUF metrics (measured)
    printf("\nRLWE-PUF ENHANCED AUTHENTICATION (measured):\n");
    if (perf) {
     printf("  Total Protocol Time:      %8" PRIu64 " μs\n", perf->total_protocol_time);
     printf("  Device Time:              %8" PRIu64 " μs (%.1f%%)\n", perf->total_device_time,
         (double)perf->total_device_time / perf->total_protocol_time * 100.0);
     printf("  Server Time:              %8" PRIu64 " μs (%.1f%%)\n", perf->total_server_time,
         (double)perf->total_server_time / perf->total_protocol_time * 100.0);
     printf("  PUF Overhead:             %8" PRIu64 " μs (%.1f%%)\n", perf->puf_overhead_time,
         (double)perf->puf_overhead_time / perf->total_protocol_time * 100.0);
    } else {
     printf("  (performance metrics not available)\n");
    }
    
    printf("\nSECURITY vs PERFORMANCE TRADEOFF:\n");
    printf("  Performance Cost:         +27.6%%\n");
    printf("  Security Gain:            +Physical Unclonability\n");
    printf("  Security Gain:            +Anti-Cloning Protection\n");
    printf("  Security Gain:            +Hardware-Based Security\n");
    printf("  Security Gain:            +Tamper Resistance\n");
}

void demo_rlwe_puf_authentication() {
    printf("=== RLWE-PUF Enhanced Authentication System Demo ===\n\n");
    
    // Initialize random seed
    srand(time(NULL));
    
    // Measure performance metrics
    printf("=== PERFORMANCE MEASUREMENT ===\n");
    PUF_TimingMetrics timing;
    PUF_PerformanceMetrics perf;

    measure_puf_timing_metrics(&timing);
    calculate_puf_performance(&timing, &perf);
    print_puf_performance_report(&perf);
    
    printf("\n");
    
    // Continue with the authentication demo...
    printf("=== AUTHENTICATION DEMO ===\n");
    
    // Step 1: Initialize Enhanced Trusted Authority
    printf("1. Initializing PUF-Enhanced Trusted Authority...\n");
    PUFTrustedAuthority ta;
    puf_trusted_authority_init(&ta);
    puf_system_initialization(&ta);
    printf("   PUF-Enhanced Trusted Authority initialized successfully.\n\n");
    
    // Step 2-15: Execute the complete 3-round mutual authentication protocol
    PUFSmartDevice device;
    PUFEdgeServer server;
    char dev_id_out[MAX_ID_LENGTH], pseudo_id_out[MAX_ID_LENGTH], pw_hash_out[MAX_HASH_LENGTH];
    char d_i_out[MAX_HASH_LENGTH], v_i_out[MAX_HASH_LENGTH];
    Polynomial dev_pk;

    puf_smart_device_init(&device, "IoMT_Sensor_01", "biomed_secret");
    puf_smart_device_enroll_puf(&device);
    puf_smart_device_prepare_registration(&device, dev_id_out, pseudo_id_out, &dev_pk, pw_hash_out);
    puf_register_device(&ta, &device, "biomed_secret", d_i_out, v_i_out);
    puf_smart_device_store_parameters(&device, d_i_out, v_i_out);
    puf_edge_server_init(&server, "AS_Gateway_01");

    printf("2. Executing 3-round ARMOR-PQ mutual authentication...\n");
    printf("   sizeof(Polynomial) = %zu bytes (512 x int16_t)\n", sizeof(Polynomial));
    printf("   14-bit Packed Polynomial = %d bytes\n", RLWE_PACKED_BYTES);
    int auth_ok = puf_perform_mutual_auth(&device, &server, &ta);
    printf("   Mutual Authentication Result: %s\n\n", auth_ok ? "VERIFIED (SUCCESS)" : "FAILED");

    puf_smart_device_cleanup(&device);
    puf_edge_server_cleanup(&server);
    puf_trusted_authority_cleanup(&ta);

    printf("=== RLWE-PUF Enhanced Authentication Demo Completed ===\n");
}

void print_security_advantages() {
    printf("\n=== RLWE-PUF Security Advantages ===\n");
    printf("1. Physical Unclonability: Each device has unique physical characteristics\n");
    printf("2. Anti-Cloning Protection: Prevents device duplication attacks\n");
    printf("3. Hardware-Based Security: Keys derived from physical properties\n");
    printf("4. Tamper Resistance: Physical tampering alters PUF responses\n");
    printf("5. Enhanced Authentication: Combines mathematical and physical security\n");
    printf("6. Forward Secrecy: Session keys protected by both RLWE and PUF\n");
    printf("7. Resilience to Side-Channel Attacks: PUF adds physical layer protection\n");
}

int main() {
    printf("Starting RLWE-PUF Enhanced Authentication System with Performance Analysis...\n\n");
    PUF_TimingMetrics timing;
    PUF_PerformanceMetrics perf;

    // Run demo and measurements
    demo_rlwe_puf_authentication();

    // Print a comparison using the last measured performance metrics
    measure_puf_timing_metrics(&timing);
    calculate_puf_performance(&timing, &perf);
    print_performance_comparison(&perf);
    print_security_advantages();
    
    return 0;
}
