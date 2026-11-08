# Evaluation artifacts

Generated outputs from the current fixed-seed evaluation runs. Per-session raw
JSON and downloaded datasets stay local and are excluded from Git; the raw
column below documents files produced by running each evaluation. Included
summaries and plots contain aggregate results. Synthetic and honeypot results
are mechanism or dataset-specific evidence, not live deployment accuracy.

| Evaluation | Raw data | Summary | Plot |
|---|---|---|---|
| Schonlau command blocks | local only: `schonlau_raw.json` | `schonlau_summary.csv` | `schonlau_roc.png` |
| Synthetic model comparison | `synthetic_raw.json` | `synthetic_summary.json` | `synthetic.png` |
| Repeated personalization | `personalization_raw.json` | `personalization_summary.json` | `personalization.png` |
| Repeated cold start | `cold_start_repeated_raw.json` | `cold_start_repeated_summary.json` | `cold_start_repeated.png` |
| Judgment / response | `judgment_raw.json` | `judgment_summary.json` | `judgment.png` |
| Drift / learning | `drift_raw.json` | `drift_summary.json`, `drift_summary.csv` | `drift.png`, `drift_gradual.png`, `drift_clear.png` |
| Engine checks, counterfactual, poisoning | `stage16_raw.json` | `stage16_summary.json` | `stage16_checks.png` |
| Cowrie temporal folds | `cowrie_multiday_raw.json` | `cowrie_multiday_summary.json`, `cowrie_multiday_summary.csv` | `cowrie_multiday.png` |
| Live SSH latency | `latency_raw.json` | `latency_summary.json` | `latency.png` |
| Local alert delivery | `alert_latency_raw.json` | `alert_latency_summary.json`, `alert_latency.csv` | `alert_latency.png` |
| Live gateway alert sessions | local only: `live_alert_sessions_raw.json` | `live_alert_sessions_summary.json` | — |
| Live PTY line capture | `capture_raw.json` | `capture_summary.json` | `capture_accuracy.png` |
| Live alternate-screen behavior | `alt_screen_raw.json` | `alt_screen_summary.json` | `alt_screen.png` |

Reproduction commands are documented beside each experiment in the project
README or in the corresponding script. Live measurements require the Docker
stack; Cowrie temporal evaluation requires the local raw downloads, which are
ignored and must be fetched separately.
