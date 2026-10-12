#include "puf_timing.h"
#include "rlwe_puf_auth.h"
#include "rlwe_core.h"
#include "puf.h"
#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include "sha_portable.h"
#include <inttypes.h>
#include <math.h>
#include <string.h>

// Get current time in microseconds
long long get_time_us() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (long long)tv.tv_sec * 1000000 + tv.tv_usec;
}

// Measure each operation multiple times (warm-up + N runs) and compute mean/stddev
void simulate_puf_operations(PUF_TimingMetrics* timing) {
    const int N = 50;
    const int W = 5; // warm-up
    uint64_t samples[N];
    int i, r;
    long long start, end;

    // We'll compute stats inline below

    // 1) PUF Enrollment: create device and enroll
    printf("Measuring PUF Enrollment (real) - %d runs (warm-up %d) ...\n", N, W);
    for (r = 0; r < W + N; r++) {
        PUFSmartDevice device;
        // warm-up runs are not recorded
        start = get_time_us();
        puf_smart_device_init(&device, "device_bench", "pw");
        puf_smart_device_enroll_puf(&device);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
        puf_smart_device_cleanup(&device);
    }
    // compute mean/stddev
    double mean_enroll = 0.0, sd_enroll = 0.0;
    for (i = 0; i < N; i++) mean_enroll += samples[i];
    mean_enroll /= N;
    for (i = 0; i < N; i++) sd_enroll += (samples[i] - mean_enroll) * (samples[i] - mean_enroll);
    sd_enroll = sqrt(sd_enroll / N);
    timing->Tpuf_enroll = (uint64_t)mean_enroll;

    // 2) PUF Response Generation
    printf("Measuring PUF Response Generation (real) - %d runs (warm-up %d) ...\n", N, W);
    // initialize a single device for response/verify/keyderive/auth measurements
    PUFSmartDevice device;
    PUFTrustedAuthority ta;
    polynomial_init(&ta.sm); polynomial_init(&ta.pm); polynomial_init(&ta.a);
    puf_trusted_authority_init(&ta); puf_system_initialization(&ta);
    puf_smart_device_init(&device, "device_bench", "pw");
    puf_smart_device_enroll_puf(&device);

    uint8_t challenge[PUF_CHALLENGE_SIZE];
    puf_generate_challenge(&device.puf, challenge);
    PUFResponse resp;
    for (r = 0; r < W + N; r++) {
        start = get_time_us();
        puf_generate_response(&device.puf, challenge, &resp, 1);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
    }
    double mean_response = 0.0, sd_response = 0.0;
    for (i = 0; i < N; i++) mean_response += samples[i];
    mean_response /= N;
    for (i = 0; i < N; i++) sd_response += (samples[i] - mean_response) * (samples[i] - mean_response);
    sd_response = sqrt(sd_response / N);
    timing->Tpuf_response = (uint64_t)mean_response;

    // 3) PUF Verification
    printf("Measuring PUF Verification (real) - %d runs (warm-up %d) ...\n", N, W);
    for (r = 0; r < W + N; r++) {
        start = get_time_us();
        puf_verify_device(&device.puf, &device.puf.enrolled_response);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
    }
    double mean_verify = 0.0, sd_verify = 0.0;
    for (i = 0; i < N; i++) mean_verify += samples[i];
    mean_verify /= N;
    for (i = 0; i < N; i++) sd_verify += (samples[i] - mean_verify) * (samples[i] - mean_verify);
    sd_verify = sqrt(sd_verify / N);
    timing->Tpuf_verify = (uint64_t)mean_verify;

    // 4) PUF Key Derivation
    printf("Measuring PUF Key Derivation (real) - %d runs (warm-up %d) ...\n", N, W);
    uint8_t derived[PUF_KEY_SIZE];
    for (r = 0; r < W + N; r++) {
        start = get_time_us();
        puf_derive_key_from_response(resp.response, derived);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
    }
    double mean_kd = 0.0, sd_kd = 0.0;
    for (i = 0; i < N; i++) mean_kd += samples[i];
    mean_kd /= N;
    for (i = 0; i < N; i++) sd_kd += (samples[i] - mean_kd) * (samples[i] - mean_kd);
    sd_kd = sqrt(sd_kd / N);
    timing->Tpuf_key_derive = (uint64_t)mean_kd;

    // 5) RLWE Authentication via smart-device initiate
    printf("Measuring RLWE Authentication (real) - %d runs (warm-up %d) ...\n", N, W);
    Polynomial server_pk, ta_pk;
    polynomial_init(&server_pk); polynomial_init(&ta_pk);
    polynomial_uniform(&server_pk); polynomial_uniform(&ta_pk);
    PUFAuthMessage auth_msg;
    int c_i[RLWE_N];
    for (r = 0; r < W + N; r++) {
        start = get_time_us();
        puf_smart_device_initiate_authentication(&device, &server_pk, &ta_pk, &auth_msg, c_i);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
    }
    double mean_rlwe = 0.0, sd_rlwe = 0.0;
    for (i = 0; i < N; i++) mean_rlwe += samples[i];
    mean_rlwe /= N;
    for (i = 0; i < N; i++) sd_rlwe += (samples[i] - mean_rlwe) * (samples[i] - mean_rlwe);
    sd_rlwe = sqrt(sd_rlwe / N);
    timing->Trlwe_auth = (uint64_t)mean_rlwe;

    // 6) Session key computation
    printf("Measuring Session Key Computation (real) - %d runs (warm-up %d) ...\n", N, W);
    char session_key[MAX_HASH_LENGTH];
    int w_i_arr[10] = {0}, sigma_i_arr[10] = {0}, w_j_arr[10] = {0}, sigma_j_arr[10] = {0};
    for (r = 0; r < W + N; r++) {
        start = get_time_us();
        puf_compute_session_key(device.pseudo_id, "server_01", &auth_msg.p_i,
                                w_i_arr, sigma_i_arr, auth_msg.alpha_i,
                                &auth_msg.p_i, w_j_arr, sigma_j_arr, auth_msg.alpha_i, auth_msg.K_hex,
                                device.v_i, session_key);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
    }
    double mean_sess = 0.0, sd_sess = 0.0;
    for (i = 0; i < N; i++) mean_sess += samples[i];
    mean_sess /= N;
    for (i = 0; i < N; i++) sd_sess += (samples[i] - mean_sess) * (samples[i] - mean_sess);
    sd_sess = sqrt(sd_sess / N);
    timing->Tsession_key = (uint64_t)mean_sess;

    // 7) Hash computation (SHA512)
    printf("Measuring Hash Computation (real) - %d runs (warm-up %d) ...\n", N, W);
    unsigned char hash_in[1024]; memset(hash_in, 0xA5, sizeof(hash_in));
    unsigned char hash_out[SHA512_DIGEST_LENGTH];
    for (r = 0; r < W + N; r++) {
        start = get_time_us();
        SHA512_simple(hash_in, sizeof(hash_in), hash_out);
        end = get_time_us();
        if (r >= W) samples[r - W] = (uint64_t)(end - start);
    }
    double mean_hash = 0.0, sd_hash = 0.0;
    for (i = 0; i < N; i++) mean_hash += samples[i];
    mean_hash /= N;
    for (i = 0; i < N; i++) sd_hash += (samples[i] - mean_hash) * (samples[i] - mean_hash);
    sd_hash = sqrt(sd_hash / N);
    timing->Thash = (uint64_t)mean_hash;

    // Print means ± stddev for transparency
    printf("\nMeasured means (μs) and stddevs:\n");
    printf("  Tpuf_enroll:   %.1f ± %.1f\n", mean_enroll, sd_enroll);
    printf("  Tpuf_response: %.1f ± %.1f\n", mean_response, sd_response);
    printf("  Tpuf_verify:   %.1f ± %.1f\n", mean_verify, sd_verify);
    printf("  Tpuf_kderive:  %.1f ± %.1f\n", mean_kd, sd_kd);
    printf("  Trlwe_auth:    %.1f ± %.1f\n", mean_rlwe, sd_rlwe);
    printf("  Tsession_key:  %.1f ± %.1f\n", mean_sess, sd_sess);
    printf("  Thash:         %.1f ± %.1f\n", mean_hash, sd_hash);

    // Cleanup
    puf_smart_device_cleanup(&device);
    puf_trusted_authority_cleanup(&ta);
}

void measure_puf_timing_metrics(PUF_TimingMetrics* timing) {
    printf("=== MEASURING ACTUAL RLWE-PUF OPERATION TIMINGS ===\n");
    simulate_puf_operations(timing);
    
    printf("\n=== ACTUAL MEASURED TIMINGS ===\n");
    printf("PUF Enrollment (Tpuf_enroll):         %4" PRIu64 " μs\n", timing->Tpuf_enroll);
    printf("PUF Response Gen (Tpuf_response):     %4" PRIu64 " μs\n", timing->Tpuf_response);
    printf("PUF Verification (Tpuf_verify):       %4" PRIu64 " μs\n", timing->Tpuf_verify);
    printf("PUF Key Derivation (Tpuf_key_derive): %4" PRIu64 " μs\n", timing->Tpuf_key_derive);
    printf("RLWE Authentication (Trlwe_auth):     %4" PRIu64 " μs\n", timing->Trlwe_auth);
    printf("Session Key Comp (Tsession_key):      %4" PRIu64 " μs\n", timing->Tsession_key);
    printf("Hash Computation (Thash):             %4" PRIu64 " μs\n", timing->Thash);
}

void calculate_puf_performance(const PUF_TimingMetrics* timing, PUF_PerformanceMetrics* perf) {
    // Calculate based on protocol flow with actual measured times
    
    // Device operations (registration + auth initiation + verification)
    perf->device_registration_time = timing->Tpuf_enroll + timing->Thash;
    perf->device_auth_init_time = timing->Tpuf_response + (timing->Trlwe_auth / 2) + timing->Thash;
    perf->device_verify_time = timing->Tpuf_verify;
    perf->total_device_time = perf->device_registration_time + perf->device_auth_init_time + perf->device_verify_time;
    
    // Server operations
    perf->server_registration_time = timing->Thash;
    perf->server_verify_time = (timing->Trlwe_auth / 2) + timing->Thash;
    perf->total_server_time = perf->server_registration_time + perf->server_verify_time;
    
    // Protocol overhead
    perf->session_key_time = timing->Tsession_key + timing->Thash;
    perf->puf_overhead_time = timing->Tpuf_enroll + timing->Tpuf_response + timing->Tpuf_verify + timing->Tpuf_key_derive;
    
    // Total protocol time (sum of all major components)
    perf->total_protocol_time = perf->total_device_time + perf->total_server_time + 
                               perf->session_key_time + (timing->Thash * 2); // Additional hash ops
    
    printf("\n=== CALCULATING PERFORMANCE FROM MEASURED TIMINGS ===\n");
}

void print_puf_performance_report(const PUF_PerformanceMetrics* perf) {
    printf("\n=== RLWE-PUF ACTUAL PERFORMANCE METRICS (μs) ===\n");
    printf("DEVICE OPERATIONS:\n");
    printf("  Registration Time:             %" PRIu64 " μs\n", perf->device_registration_time);
    printf("  Authentication Init:           %" PRIu64 " μs\n", perf->device_auth_init_time);
    printf("  Server Verify Time:            %" PRIu64 " μs\n", perf->device_verify_time);
    printf("  %s\n", "──────────────────────────────────");
    printf("  TOTAL DEVICE TIME:             %" PRIu64 " μs\n", perf->total_device_time);
    
    printf("\nSERVER OPERATIONS:\n");
    printf("  Registration Time:             %" PRIu64 " μs\n", perf->server_registration_time);
    printf("  Device Verify Time:            %" PRIu64 " μs\n", perf->server_verify_time);
    printf("  %s\n", "──────────────────────────────────");
    printf("  TOTAL SERVER TIME:             %" PRIu64 " μs\n", perf->total_server_time);
    
    printf("\nPROTOCOL OVERHEAD:\n");
    printf("  Session Key Computation:       %" PRIu64 " μs\n", perf->session_key_time);
    printf("  PUF Security Overhead:         %" PRIu64 " μs\n", perf->puf_overhead_time);
    printf("  %s\n", "──────────────────────────────────");
    printf("  TOTAL PROTOCOL TIME:           %" PRIu64 " μs\n", perf->total_protocol_time);
    
    // Calculate percentages
    float device_percent = (float)perf->total_device_time / perf->total_protocol_time * 100;
    float server_percent = (float)perf->total_server_time / perf->total_protocol_time * 100;
    float puf_percent = (float)perf->puf_overhead_time / perf->total_protocol_time * 100;
    float session_percent = (float)perf->session_key_time / perf->total_protocol_time * 100;
    float hash_percent = 100.0f - device_percent - server_percent - puf_percent - session_percent;
    
    printf("\nBREAKDOWN ANALYSIS:\n");
    printf("  Device %% of total:             %.1f%%\n", device_percent);
    printf("  Server %% of total:             %.1f%%\n", server_percent);
    printf("  PUF Overhead %%:               %.1f%%\n", puf_percent);
    printf("  Session Key %%:                %.1f%%\n", session_percent);
    printf("  Hash Operations %%:            %.1f%%\n", hash_percent);
    
    printf("\nCOMPARISON WITH BASIC RLWE:\n");
    printf("  Basic RLWE Time:               ~862 μs (estimated)\n");
    printf("  RLWE-PUF Time:                 %" PRIu64 " μs\n", perf->total_protocol_time);
    
    if (perf->total_protocol_time > 862) {
        float security_cost = ((float)perf->total_protocol_time - 862.0f) / 862.0f * 100.0f;
        printf("  PUF Security Cost:             +%.1f%%\n", security_cost);
    } else {
        printf("  PUF Security Cost:             NEGATIVE (faster than basic RLWE)\n");
    }
    
    printf("\n📊 PERFORMANCE ASSESSMENT:\n");
    printf("  Authentication Time:           %" PRIu64 " μs (%.2f ms)\n", 
           perf->total_protocol_time, (float)perf->total_protocol_time / 1000.0f);
    printf("  Suitability for IoT:           %s\n", 
           perf->total_protocol_time < 2000 ? "EXCELLENT" : "GOOD");
    printf("  Real-time Capability:          %s\n", 
           perf->total_protocol_time < 1000 ? "YES" : "MODERATE");
}
