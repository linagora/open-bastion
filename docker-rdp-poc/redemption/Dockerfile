# Stage 1: Build Redemption
FROM debian:trixie-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    g++ \
    libboost-tools-dev \
    libboost-test-dev \
    libboost-build-dev \
    pkg-config \
    gettext \
    git \
    ca-certificates \
    zlib1g-dev \
    libssl-dev \
    libkrb5-dev \
    libsnappy-dev \
    libpng-dev \
    libbz2-dev \
    libhyperscan-dev \
    libavcodec-dev \
    libavformat-dev \
    libavutil-dev \
    libswscale-dev \
    libx264-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
RUN git clone --depth 1 https://github.com/wallix/redemption.git

WORKDIR /src/redemption
RUN bjam -j$(nproc) toolset=gcc exe libs \
    && bjam install

# Stage 2: Runtime image
FROM debian:trixie-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    libkrb5-3 \
    libsnappy1v5 \
    libpng16-16t64 \
    libbz2-1.0 \
    libhyperscan5 \
    zlib1g \
    libavcodec60 \
    libavformat60 \
    libavutil58 \
    libswscale7 \
    libx264-164 \
    python3 \
    python3-requests \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/bin/rdpproxy /usr/local/bin/
COPY --from=builder /usr/local/bin/redrec /usr/local/bin/
COPY --from=builder /usr/local/lib/ /usr/local/lib/

RUN ldconfig

RUN mkdir -p /etc/rdpproxy \
    /var/lib/llng-sessions/rdp \
    /var/log/rdpproxy \
    /var/run/rdpproxy

RUN useradd -r -s /sbin/nologin rdpproxy \
    && chown -R rdpproxy:rdpproxy /var/lib/llng-sessions/rdp \
    /var/log/rdpproxy \
    /var/run/rdpproxy

COPY --chmod=755 config/passthrough.py /etc/rdpproxy/passthrough.py

COPY config/rdpproxy.ini /etc/rdpproxy/rdpproxy.ini

# PoC only: self-signed certificate, not for production use.
RUN openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/rdpproxy/key.pem \
    -out /etc/rdpproxy/cert.pem \
    -subj "/CN=rdp-proxy/O=LLNG-PoC" \
    && chown rdpproxy:rdpproxy /etc/rdpproxy/*.pem

EXPOSE 3389

USER rdpproxy

CMD ["rdpproxy", "-c", "/etc/rdpproxy/rdpproxy.ini"]
