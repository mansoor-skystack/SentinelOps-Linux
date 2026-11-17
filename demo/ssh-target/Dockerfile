FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends openssh-server passwd \
    && rm -f /etc/ssh/ssh_host_*_key /etc/ssh/ssh_host_*_key.pub \
    && rm -f /etc/ssl/private/ssl-cert-snakeoil.key \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /bin/sh sentinelops-demo \
    && passwd -d sentinelops-demo \
    && mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/sbin/sentinelops-demo-sshd
RUN chmod 755 /usr/local/sbin/sentinelops-demo-sshd

ENTRYPOINT ["/usr/local/sbin/sentinelops-demo-sshd"]
