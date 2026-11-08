#!/bin/sh
set -eu
if [ ! -f /run/secrets/czts_upstream.pub ]; then echo 'Missing mounted upstream public key'; exit 1; fi
install -o czt-demo -g czt-demo -m 0700 -d /home/czt-demo/.ssh
install -o czt-demo -g czt-demo -m 0600 /run/secrets/czts_upstream.pub /home/czt-demo/.ssh/authorized_keys
ssh-keygen -A
install -o root -g root -m 0600 /run/secrets/czts_target_host /etc/ssh/ssh_host_ed25519_key
ssh-keygen -y -f /etc/ssh/ssh_host_ed25519_key > /etc/ssh/ssh_host_ed25519_key.pub
chmod 0644 /etc/ssh/ssh_host_ed25519_key.pub
sed -i 's/^#\?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
exec /usr/sbin/sshd -D -e -h /etc/ssh/ssh_host_ed25519_key
