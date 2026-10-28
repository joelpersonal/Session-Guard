# TABLE II: Performance Breakdown by Scenario (S1–S8)

*Data Source: `results/raw/evaluation_runs.csv` | Total Evaluated Rows: 480*

| Scenario | Description | Ground Truth | Token-Only | Network Binding | Network + UA | SessionGuard |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: |
| **S1** | Normal session (no anomalies) | Benign | ✓ Allowed (100%) | ✓ Allowed (100%) | ✓ Allowed (100%) | ✓ Allowed (100%) |
| **S2** | Legitimate network change mid-session | Benign | ✓ Allowed (100%) | ✗ Blocked (100% FP) | ✗ Blocked (100% FP) | ✓ Allowed (100%) |
| **S3** | Stolen token: Foreign network + foreign UA (A1) | Attack | ✗ Missed (100% FN) | ✓ Detected (100%) | ✓ Detected (100%) | ✓ Detected (100%) |
| **S4** | Stolen token: Same network + spoofed UA (A2) | Attack | ✗ Missed (100% FN) | ✗ Missed (100% FN) | ✗ Missed (100% FN) | ✓ Detected (100%) |
| **S5** | Concurrent interleaved credential use (D1↔D2) | Attack | ✗ Missed (100% FN) | ✓ Detected (100%) | ✓ Detected (100%) | ✓ Detected (100%) |
| **S6** | Sensitive action from anomalous context | Attack | ✗ Missed (100% FN) | ✓ Detected (100%) | ✓ Detected (100%) | ✓ Detected (100%) |
| **S7** | Legitimate sensitive action (benign check) | Benign | ✓ Allowed (100%) | ✓ Allowed (100%) | ✓ Allowed (100%) | ✓ Allowed (100%) |
| **S8** | Legitimate multi-device sequential (benign check) | Benign | ✓ Allowed (100%) | ✓ Allowed (100%) | ✓ Allowed (100%) | ✓ Allowed (100%) |
