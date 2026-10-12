#ifndef PUF_TIMING_H
#define PUF_TIMING_H

#include <stdint.h>

typedef struct {
    uint64_t Tpuf_enroll;
    uint64_t Tpuf_response;
    uint64_t Tpuf_verify;
    uint64_t Tpuf_key_derive;
    uint64_t Trlwe_auth;
    uint64_t Tsession_key;
    uint64_t Thash;
} PUF_TimingMetrics;

typedef struct {
    uint64_t device_registration_time;
    uint64_t device_auth_init_time;
    uint64_t device_verify_time;
    uint64_t server_registration_time;
    uint64_t server_verify_time;
    uint64_t session_key_time;
    uint64_t total_device_time;
    uint64_t total_server_time;
    uint64_t total_protocol_time;
    uint64_t puf_overhead_time;
} PUF_PerformanceMetrics;

void measure_puf_timing_metrics(PUF_TimingMetrics* timing);
void calculate_puf_performance(const PUF_TimingMetrics* timing, PUF_PerformanceMetrics* perf);
void print_puf_performance_report(const PUF_PerformanceMetrics* perf);

#endif
