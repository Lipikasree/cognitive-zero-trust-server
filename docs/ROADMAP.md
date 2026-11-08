# MVP delivery status

Status for the Windows-hosted Cognitive Zero Trust Server MVP. This records
what was implemented and measured in the current working tree.

## Delivered and verified

- A0: Clean virtual environment, test suite, bytecode compilation, and Docker
  Compose configuration checks.
- A1: Schonlau evaluation with per-user/global/frequency/second-order and
  likelihood-ratio comparisons, validation-only selection, untouched held-out
  blocks, ROC/AUC, and CSV/JSON/plot artifacts.
- A2: Ten-seed synthetic drift comparison for gradual and clear changes,
  separate static/automatic/feedback arms, bootstrap intervals, and score
  trajectories. Ground-truth benign labels make the feedback arm optimistic.
- A3: Live PTY capture check for ordinary/corrected lines, fail-closed arrow
  and Tab handling, and a live alternate-screen transition check. Full-screen
  application input is not inspected.
- A4: Grafana alert fan-out includes local capture and Brevo email, grouped per
  session. Five restricted and five discarded sessions were driven through the
  real SSH gateway. The local webhook captured 10 restricted transitions (five
  later discarded) and five discarded transitions. Gateway-event-to-local-
  webhook delay: restricted median 77.820s, worst 82.942s; discarded median
  68.554s, worst 71.601s. These are not inbox arrival measurements. SMTP
  authentication succeeded; the user confirmed both the test email and real
  incident alerts arrived in Gmail around 7:12–7:16 pm IST. That approximate
  range overlaps the alert batch but starts before its first event, so per-alert
  median/worst event-to-inbox delay is not calculated.
- A5: Six-day COW160 download and expanding temporal evaluation across 276,512
  sessions. Test folds use only earlier days for training; the gateway-ready
  temporal export marks four days train and two test.
- A6: Key-management and deployment documentation, isolated target network,
  unprivileged gateway container, pinned upstream host key, and local admin
  controls.
- A7: Repeatable synthetic, judgment, cold-start, personalization, poisoning,
  counterfactual, latency, capture, and alert measurement artifacts. A clean
  environment has 35 passing tests; compile and Compose validation passed.

## Remaining boundaries

- Per-alert event-to-inbox arrival timing remains unmeasured; the user confirmed
  receipt of the live emails only to an approximate time range. The measured
  delays end at local webhook receipt. Delivery also depends on the sender
  remaining verified and Brevo account active.
- The gateway is a Dockerized service hosted on Windows, not a native Windows
  process. The Ubuntu target remains private to the gateway network.
- Interactive SSH remains a prototype with documented terminal limitations.
  High-cost categories require TOTP; ambiguous lower-cost step-up remains
  inline confirmation.
- Schonlau held-out false-positive rates differ from nominal validation targets.
  Synthetic benchmarks and Cowrie honeypot traffic do not establish live
  production accuracy.
- No video recording or Git commit is included, per the user's instruction.

Detailed run artifacts are indexed in `eval/results/README.md`.
