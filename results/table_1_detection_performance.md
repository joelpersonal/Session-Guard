# TABLE I: Detection Performance Across Methods (Evaluation Partition)

*Data Source: `results/raw/evaluation_runs.csv` | Total Evaluated Rows: 480*

| Method | TP | FP | TN | FN | Detection Rate (Recall) | Precision | F1 Score | FP Rate |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Token-Only** | 0 | 0 | 60 | 60 | 0.0% | 0.0% | 0.000 | 0.0% |
| **Network Binding** | 45 | 15 | 45 | 15 | 75.0% | 75.0% | 0.750 | 25.0% |
| **Network + User-Agent** | 45 | 15 | 45 | 15 | 75.0% | 75.0% | 0.750 | 25.0% |
| **SessionGuard** | 60 | 0 | 60 | 0 | 100.0% | 100.0% | 1.000 | 0.0% |
