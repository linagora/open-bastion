# LLNG SSH Backend (Unconfigured) - For Enrollment Demo
#
# This container is NOT pre-configured with a server token.
# It must be enrolled manually using the Device Authorization flow.

FROM debian:13-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    libcurl4-gnutls-dev \
    libjson-c-dev \
    libssl-dev \
    libpam0g-dev \
    curl \
    jq \
    cmake \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/run/sshd \
    /var/cache/pam_llng \
    /var/cache/nss_llng \
    && chmod 750 /var/cache/pam_llng \
    && chmod 750 /var/cache/nss_llng

# Build PAM and NSS modules from source
COPY CMakeLists.txt /src/llng-pam-module/
COPY src/ /src/llng-pam-module/src/
COPY include/ /src/llng-pam-module/include/
COPY nss/ /src/llng-pam-module/nss/
COPY scripts/ /src/llng-pam-module/scripts/
WORKDIR /src/llng-pam-module
RUN mkdir -p build && cd build && \
    cmake -DBUILD_TESTING=OFF .. && \
    make -j$(nproc) && \
    cp pam_llng.so /usr/lib/x86_64-linux-gnu/security/ && \
    cp nss/libnss_llng.so.2 /lib/x86_64-linux-gnu/ && \
    cp ../scripts/llng-pam-enroll /usr/sbin/ && \
    chmod 755 /usr/sbin/llng-pam-enroll && \
    ldconfig && \
    cd / && rm -rf /src/llng-pam-module/build

# NO configuration is done here - this simulates a fresh installation
# PAM, NSS, and SSHD must be configured manually following the README

# Fix PAM loginuid for Docker (standard Debian issue)
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Startup script (minimal - no token configuration)
COPY docker/backend-new/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
