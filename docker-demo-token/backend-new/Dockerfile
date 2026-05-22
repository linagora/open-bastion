# Open Bastion SSH Backend (Unconfigured) - For Enrollment Demo
#
# This container is NOT pre-configured with a server token.
# It must be enrolled manually using the Device Authorization flow.

FROM debian:13-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    nscd \
    sudo \
    libcurl4-gnutls-dev \
    libjson-c-dev \
    libssl-dev \
    libpam0g-dev \
    curl \
    jq \
    openssl \
    cmake \
    gcc \
    make \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/run/sshd \
    /var/cache/open-bastion \
    && chmod 750 /var/cache/open-bastion

# Build PAM and NSS modules from source
COPY CMakeLists.txt /src/open-bastion/
COPY src/ /src/open-bastion/src/
COPY include/ /src/open-bastion/include/
COPY nss/ /src/open-bastion/nss/
COPY scripts/ /src/open-bastion/scripts/
COPY config/ /src/open-bastion/config/
COPY README.md /src/open-bastion/README.md
COPY man/ /src/open-bastion/man/
WORKDIR /src/open-bastion
# `make install` with CMAKE_INSTALL_PREFIX=/usr puts every ob-* script at the
# same path the production .deb does (/usr/sbin/ob-enroll, /usr/bin/ob-ssh-cert,
# etc.). New scripts added to CMakeLists.txt land in the demo automatically;
# no per-Dockerfile allowlist to maintain.
RUN mkdir -p build && cd build && \
    cmake -DCMAKE_INSTALL_PREFIX=/usr \
          -DBUILD_TESTING=OFF \
          -DINSTALL_SYSTEMD=OFF \
          -DINSTALL_DESKTOP=OFF \
          -DBUILD_BUILDER=OFF \
          .. && \
    make -j$(nproc) && \
    make install && \
    # NSS loader (libc) traditionally searches /lib/x86_64-linux-gnu first.
    # On merged-/usr Debian /lib IS /usr/lib, so the symlink would self-loop.
    # Only create the link when the two directories are genuinely distinct.
    { if [ "$(readlink -f /lib/x86_64-linux-gnu)" != "$(readlink -f /usr/lib/x86_64-linux-gnu)" ]; then ln -sf /usr/lib/x86_64-linux-gnu/libnss_openbastion.so.2 /lib/x86_64-linux-gnu/libnss_openbastion.so.2; fi ; } && \
    ldconfig && \
    cd / && rm -rf /src/open-bastion/build

# NO configuration is done here - this simulates a fresh installation
# PAM, NSS, and SSHD must be configured manually following the README

# Fix PAM loginuid for Docker (standard Debian issue)
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Startup script (minimal - no token configuration)
COPY docker-demo-token/backend-new/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
