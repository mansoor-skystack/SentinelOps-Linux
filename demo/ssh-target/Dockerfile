FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server passwd \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /bin/sh sentinelops-demo \
    && passwd -d sentinelops-demo \
    && mkdir -p /run/sshd

COPY sshd_config /etc/ssh/sshd_config
COPY entrypoint.sh /usr/local/sbin/sentinelops-demo-sshd
RUN chmod 755 /usr/local/sbin/sentinelops-demo-sshd

ENTRYPOINT ["/usr/local/sbin/sentinelops-demo-sshd"]
