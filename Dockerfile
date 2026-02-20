ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.11-alpine3.18
FROM ${BUILD_FROM}

ARG VIPSY_CF_TOKEN=""
ARG VIPSY_CF_ACCOUNT_ID=""
ARG VIPSY_CF_ZONE_ID=""
ARG VIPSY_CF_DOMAIN=""

ENV VIPSY_CF_TOKEN=${VIPSY_CF_TOKEN} \
    VIPSY_CF_ACCOUNT_ID=${VIPSY_CF_ACCOUNT_ID} \
    VIPSY_CF_ZONE_ID=${VIPSY_CF_ZONE_ID} \
    VIPSY_CF_DOMAIN=${VIPSY_CF_DOMAIN}

RUN apk add --no-cache \
    caddy \
    coturn \
    nftables \
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

RUN sed -i 's/\r$//' /run.sh \
    && chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
