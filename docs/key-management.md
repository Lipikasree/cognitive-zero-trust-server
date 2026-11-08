# Key management

## Locations and purpose

The demo keeps key files under the project `keys/` directory on the Windows
host. Docker Compose bind-mounts only the gateway host private key, upstream
client private key, pinned target host key file, and target authorized public
key into the containers. Keep this directory on persistent, access-controlled
storage and exclude it from backups that are accessible to untrusted users.

- `gateway_host`: SSH host identity presented by the gateway to clients.
- `upstream`: gateway-only client identity accepted by the target.
- `target_host`: target SSH host identity, pinned by the gateway.
- `alice_client`: local demo client identity; replace it for each operator.
- `upstream_known_hosts`: target host-key pin used by the gateway.
- `totp_secrets.json`: per-user TOTP seeds mounted read-only into the gateway.

The `keys/` directory is excluded by `.gitignore`. Never copy private keys into
logs, issue reports, screenshots, source control, or a shared folder.

## Initial generation

From the project root, run:

```powershell
python scripts/generate_keys.py
```

The script creates missing Ed25519 keys, writes matching public keys, updates
the demo user's configured public keys, and writes the target pin. On Windows
it removes inherited ACLs from private key files and grants access to the
current account and SYSTEM. Treat the demo client key as disposable; use a
separate key per real user and remove its public key when access is revoked.

Run `python scripts/enroll_totp.py <username>` to generate a provisioning QR
and a TOTP seed for an enabled account. The QR and seed file are credentials;
the script restricts the seed file ACL to the current Windows account and
SYSTEM. Scan the QR, delete it, then recreate the gateway to refresh its
read-only mount. Use `--replace` only for a planned TOTP reset. Keep a
protected recovery copy of the seed file so users can recover access.

## Rotation

The MVP does not rotate keys automatically. Plan a maintenance window and
maintain a protected backup before rotation. Do not delete the current key
until the replacement path has been tested.

### Gateway host key

1. Generate a replacement Ed25519 key in a protected temporary location.
2. Arrange client trust for its new public-key fingerprint through a trusted
   channel; do not rely on accepting an unknown key prompt.
3. Replace `keys/gateway_host` atomically, apply the same Windows ACL as the
   original, and restart the gateway container.
4. Verify clients report the expected new fingerprint, then securely retire
   the old key and backup.

### Target host key

1. Generate a replacement Ed25519 target key and update
   `keys/upstream_known_hosts` with its verified public key and target aliases.
2. Replace `keys/target_host`, preserving root-only access inside the target.
3. Recreate the target and gateway containers, then verify an upstream SSH
   command succeeds with host-key checking enabled.
4. Retire the old key after the new pin and target identity have been verified.

### Upstream and user client keys

For an upstream key, install its replacement public key in the target's
`authorized_keys` before replacing `keys/upstream`; then recreate the target and
gateway and verify forwarding. Remove the old public key after successful
verification. For a user key, add the new public key to that account's
configuration, deliver the private key securely out of band, verify login with
the replacement, then remove the old public key.

## Production workflow still needed

The current Compose target initializes its authorized key during container
startup. Production operations should use an audited secret manager, separate
per-user identities, scheduled rotation with overlap and revocation tracking,
fingerprint inventory, and tested recovery from a failed rotation. The demo
script is not a key-management service.
