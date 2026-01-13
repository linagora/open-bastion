# WALLIX Redemption RDP Proxy
# Build from source for LLNG integration
#
# This Dockerfile builds Redemption from source with Python passthrough
# authentication hook support for LemonLDAP::NG integration.
#
# Build time: ~30-60 minutes (caching recommended)

# Stage 1: Build Redemption
FROM debian:trixie-slim AS builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Build tools
    g++ \
    libboost-tools-dev \
    libboost-test-dev \
    libboost-build-dev \
    pkg-config \
    gettext \
    git \
    ca-certificates \
    # Core libraries
    zlib1g-dev \
    libssl-dev \
    libkrb5-dev \
    libsnappy-dev \
    libpng-dev \
    libbz2-dev \
    libhyperscan-dev \
    # FFmpeg for video conversion
    libavcodec-dev \
    libavformat-dev \
    libavutil-dev \
    libswscale-dev \
    libx264-dev \
    # Python for passthrough hook
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# Clone Redemption repository
WORKDIR /src
RUN git clone --depth 1 https://github.com/wallix/redemption.git

# Build Redemption
WORKDIR /src/redemption
RUN bjam -j$(nproc) toolset=gcc exe libs \
    && bjam install

# Stage 2: Runtime image
FROM debian:trixie-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Runtime libraries
    libssl3 \
    libkrb5-3 \
    libsnappy1v5 \
    libpng16-16t64 \
    libbz2-1.0 \
    libhyperscan5 \
    zlib1g \
    # FFmpeg runtime
    libavcodec60 \
    libavformat60 \
    libavutil58 \
    libswscale7 \
    libx264-164 \
    # Python for passthrough
    python3 \
    python3-requests \
    # Utilities
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy built binaries from builder
COPY --from=builder /usr/local/bin/rdpproxy /usr/local/bin/
COPY --from=builder /usr/local/bin/redrec /usr/local/bin/
COPY --from=builder /usr/local/lib/ /usr/local/lib/

# Update library cache
RUN ldconfig

# Create directories
RUN mkdir -p /etc/rdpproxy \
    /var/lib/llng-sessions/rdp \
    /var/log/rdpproxy \
    /var/run/rdpproxy

# Create non-root user for proxy
RUN useradd -r -s /sbin/nologin rdpproxy \
    && chown -R rdpproxy:rdpproxy /var/lib/llng-sessions/rdp \
    /var/log/rdpproxy \
    /var/run/rdpproxy

# Copy passthrough script template
COPY --chmod=755 config/passthrough.py /etc/rdpproxy/passthrough.py

# Copy default configuration
COPY config/rdpproxy.ini /etc/rdpproxy/rdpproxy.ini

# Expose RDP port
EXPOSE 3389

# Run as non-root
USER rdpproxy

# Start rdpproxy
CMD ["rdpproxy", "-c", "/etc/rdpproxy/rdpproxy.ini"]
