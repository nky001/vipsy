ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.11-alpine3.18
FROM ${BUILD_FROM}

ARG VIPSY_BACKEND_URL="https://vipsy-backend.nitinexus.workers.dev"

ENV VIPSY_BACKEND_URL=${VIPSY_BACKEND_URL}

RUN apk add --no-cache \
    caddy \
    coturn \
    nftables \
    wireguard-tools \
    iproute2 \
    iptables \
    curl \
    jq \
    openssl \
    bash

RUN ARCH="$(apk --print-arch)" && \
    case "$ARCH" in \
        x86_64) CF_ARCH="amd64" ;; \
        aarch64) CF_ARCH="arm64" ;; \
        armv7l|armhf) CF_ARCH="arm" ;; \
        i386|i686) CF_ARCH="386" ;; \
        *) CF_ARCH="amd64" ;; \
    esac && \
    wget -q -O /usr/local/bin/cloudflared \
        "https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-${CF_ARCH}" && \
    chmod +x /usr/local/bin/cloudflared

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY rootfs /
COPY logo.png /server/static/logo.png

RUN find /run.sh /caddy /server /coturn -type f \( -name '*.sh' -o -name '*.conf' -o -name '*.py' \) \
    -exec sed -i 's/\r$//' {} + \
    && sed -i 's/\r$//' /run.sh \
    && chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
