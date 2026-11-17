#!/bin/sh
set -eu

test -s /run/demo-keys/demo_host_ed25519
test -s /run/demo-keys/demo_client_ed25519.pub
mkdir -p /run/sshd
exec /usr/sbin/sshd -D -e -f /etc/ssh/sshd_config
