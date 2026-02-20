ARG BUILD_FROM=ghcr.io/home-assistant/amd64-base-python:3.11-alpine3.18
FROM ${BUILD_FROM}

RUN apk add --no-cache \
    caddy \
    coturn \
    nftables \
    curl \
    jq \
    openssl \
    bash

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY rootfs /
COPY logo.png /server/static/logo.png

RUN sed -i 's/\r$//' /run.sh \
    && chmod +x /run.sh

ENTRYPOINT ["/run.sh"]
