# Limits

- Interactive PTY capture inspects typed shell command lines. Arrow-key and Tab input fails closed. Commands typed inside full-screen programs such as `vim`, `less`, and `top` are not inspected; alternate-screen use is marked partly unmonitored.
- The gateway is a Docker service hosted on Windows, not a native Windows process. The sample target is a private Ubuntu container.
- Command rules supplement target operating-system permissions; they do not replace them. A target-side command hook is not included.
- TOTP is used for configured high-cost command categories. Lower-cost uncertainty challenges use inline confirmation.
- Schonlau contains command names and user labels, not command arguments. Its held-out false-positive rates can differ from validation targets.
- Cowrie is honeypot traffic. Synthetic benign sessions and synthetic drift runs do not represent production users.
- The evaluation results describe their specific datasets and scripted scenarios. They do not establish live production accuracy.
- Alert timings measure gateway event to local webhook receipt. Email delivery was confirmed by hand, but inbox arrival was not timed per alert.
- Remote email delivery requires a verified sender and valid SMTP configuration. The example `.env` leaves SMTP disabled.
- There is no high-availability gateway, remote admin API, automatic key rotation, or production secret manager.
