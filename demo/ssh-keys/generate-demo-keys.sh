#!/bin/sh
set -eu

mkdir -p /ssh-client /ssh-target /db-tls
if [ ! -s /ssh-target/demo_host_ed25519 ]; then
    ssh-keygen -q -t ed25519 -N "" -f /ssh-target/demo_host_ed25519
fi
if [ ! -s /ssh-client/demo_client_ed25519 ]; then
    ssh-keygen -q -t ed25519 -N "" -f /ssh-client/demo_client_ed25519
fi

ssh-keygen -y -f /ssh-target/demo_host_ed25519 > /ssh-target/demo_host_ed25519.pub
ssh-keygen -y -f /ssh-client/demo_client_ed25519 > /ssh-target/demo_client_ed25519.pub
cp /ssh-target/demo_host_ed25519.pub /ssh-client/demo_host_ed25519.pub
printf "ssh-target " > /ssh-client/known_hosts
cat /ssh-target/demo_host_ed25519.pub >> /ssh-client/known_hosts
chmod 600 /ssh-target/demo_host_ed25519 /ssh-client/demo_client_ed25519
chmod 644 /ssh-target/demo_host_ed25519.pub /ssh-target/demo_client_ed25519.pub
chmod 644 /ssh-client/demo_host_ed25519.pub /ssh-client/known_hosts
chown root:root /ssh-target/demo_host_ed25519 /ssh-target/demo_host_ed25519.pub
chown 10001:10001 /ssh-client/demo_client_ed25519

if [ ! -s /db-tls/postgres_server.key ] || [ ! -s /db-tls/postgres_server.crt ]; then
    openssl req -x509 -nodes -newkey rsa:2048 -days 3650 \
        -keyout /db-tls/postgres_server.key \
        -out /db-tls/postgres_server.crt \
        -subj "/CN=db" \
        -addext "subjectAltName=DNS:db"
fi
chmod 600 /db-tls/postgres_server.key
chmod 644 /db-tls/postgres_server.crt
chown 999:999 /db-tls/postgres_server.key /db-tls/postgres_server.crt
