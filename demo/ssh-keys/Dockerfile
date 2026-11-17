FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-client openssl \
    && rm -rf /var/lib/apt/lists/*

COPY generate-demo-keys.sh /usr/local/bin/generate-demo-keys
RUN chmod 755 /usr/local/bin/generate-demo-keys

ENTRYPOINT ["/usr/local/bin/generate-demo-keys"]
