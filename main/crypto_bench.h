#pragma once

/* On-device microbenchmark of the OTA cryptography, compiled in only when
 * OTA_RUN_CRYPTO_BENCHMARK is 1 (see app_config.h). Prints "BENCH" lines. */
void crypto_bench_run(void);
