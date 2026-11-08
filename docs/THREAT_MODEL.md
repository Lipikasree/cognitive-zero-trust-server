# Threat model

## System boundary

The gateway accepts SSH client keys, captures exec commands and a limited
interactive shell line buffer, evaluates each submitted command, and connects
to a configured Linux target with a separate gateway-held key. The bundled
Compose target has no host-published SSH port and is on a private network shared
only with the gateway. This is a local MVP deployment, not a hardened production
bastion.

## Covered risks and controls

- **Stolen client key / unauthorized login:** only configured public keys are
  accepted; failed authentication is rate-limited and can lock an account.
- **Session hijack or unusual behavior after login:** command rules, per-user
  transition likelihood, and decaying trust are evaluated throughout the
  session. Risky actions can be blocked, challenged, or cause session discard.
- **Accidental exposure of upstream access:** the client does not choose the
  upstream identity; the gateway uses its own key and verifies the configured
  target host key.
- **Learning-data poisoning:** only delayed clean sessions are automatically
  eligible for profile updates; admin labels and learning events are audited.
- **Accidental credential logging:** known secret-shaped command arguments are
  redacted, and authentication prompt data is not recorded as commands.
- **High-cost command misuse:** high-cost categories require a current TOTP
  code; accepted time steps are one-use in SQLite. Three failed entries block
  that command. Lower-cost uncertainty challenges use inline confirmation.
- **Gateway restart with dangling sessions:** startup reconciles persisted
  sessions into a restricted fail-closed end state.

## Not covered or only partially covered

- A compromised Windows host, Docker daemon, gateway process, administrator
  account, or private key can bypass these controls.
- In the bundled Compose deployment, only the gateway joins the private target
  network and no target SSH port is published to the Windows host. A Docker or
  host administrator can still attach another container or change the Compose
  network, so this does not protect against a hostile host administrator.
- Interactive capture disables target Readline completion and common arrow-key
  history bindings. Tab and escape-sequence edits fail closed. Common alternate-
  screen terminal sequences are logged as partly-unmonitored intervals; trust
  decays over those intervals. Commands and effects inside the application are
  still not inspected, and the terminal relay remains a prototype.
- A second-order command model can be evaded by an attacker who imitates normal
  command sequences; it cannot see intent or activity inside processes.
- TOTP seeds are stored in a local JSON file protected by Windows ACLs and
  mounted read-only into the gateway; they are not encrypted by this MVP.
  Host or administrator compromise can expose them. There is no
  high-availability gateway or remote admin API. Discord alert forwarding
  requires an operator-created webhook URL in `.env` and an end-to-end test.
- Schonlau evaluation uses benchmark command-name blocks; Cowrie temporal folds
  use honeypot attacker sessions. Neither is a measurement of live gateway
  detection or production accuracy. Synthetic drift assumes known labels in
  its feedback arm.

## Operator assumptions

Run only in a disposable local environment until network isolation, key
rotation, host monitoring, backup/recovery, and independent security review are
complete. Keep `.env`, private keys, raw third-party datasets, and event stores
out of source control. Grant gateway users only the target permissions they
need; the gateway policy is defense in depth and does not replace OS access
controls.
