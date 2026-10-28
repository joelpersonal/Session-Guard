# TABLE III: Latency and Containment Timings

*Data Source: `results/raw/evaluation_runs.csv` | Measured on active local server*

| Metric | Token-Only | Network Binding | Network + User-Agent | SessionGuard |
| :--- | :---: | :---: | :---: | :---: |
| **Detection Latency (ms)** | n/a (No Detection) | 1.32 ± 0.53 ms | 1.35 ± 0.63 ms | 2.08 ± 2.45 ms |
| **Time-to-Containment (ms)** | unbounded (n/a) | unbounded (n/a)* | unbounded (n/a)* | 1.67 ± 0.47 ms |
| **Notification Latency (ms)** | n/a | n/a | n/a | 1.13 ± 0.34 ms |

**Note: Baseline methods (Network Binding, Network+UA) reject the immediate HTTP request but have no session-revocation engine or refresh-token family invalidator, leaving the stolen credential unbounded/valid in Redis for future requests.*
