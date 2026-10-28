# TABLE IV: Scalability and Runtime Overhead (S9 Load Test)

*Data Source: `results/raw/load_test_results.json` | Evaluated with autocannon across concurrency tiers*

| Concurrent Sessions | Baseline (Off) Mean Latency | Baseline (Off) p95 Latency | Baseline Req/s | SessionGuard Mean Latency | SessionGuard p95 Latency | SessionGuard Req/s | Overhead (Mean Δ) | Overhead (p95 Δ) | % Overhead | CPU (%) | Memory (MB) |
| :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **100** | 43.05 ms | 78.00 ms | 2,322 | 260.24 ms | 369.00 ms | 400 | +217.19 ms | +291.00 ms | +504.5% | 18% | 374 MB |
| **500** | 168.32 ms | 534.00 ms | 597 | 528.95 ms | 646.00 ms | 165 | +360.63 ms | +112.00 ms | +214.3% | 18% | 389 MB |
| **1,000** | 511.35 ms | 660.00 ms | 393 | 758.62 ms | 1042.00 ms | 309 | +247.27 ms | +382.00 ms | +48.4% | 18% | 527 MB |
| **5,000** | 508.15 ms | 1208.00 ms | 393 | 985.24 ms | 1165.00 ms | 197 | +477.09 ms | +0.01 ms | +93.9% | 18% | 527 MB |
| **10,000** | 369.93 ms | 640.00 ms | 567 | 796.34 ms | 995.00 ms | 197 | +426.41 ms | +355.00 ms | +115.3% | 18% | 520 MB |
