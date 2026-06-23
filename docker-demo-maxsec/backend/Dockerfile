# Open Bastion SSH Backend - Maximum Security Mode E
#
# This container provides:
# - SSH certificate authentication ONLY (no authorized_keys)
# - Key Revocation List (KRL) enforcement
# - Automatic user creation from Open Bastion attributes
# - NSS module for user/group resolution
# - Sudo via LLNG temporary token only (not NOPASSWD)
# - Bastion JWT verification

FROM debian:13-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    cron \
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
    /etc/open-bastion \
    && chmod 750 /var/cache/open-bastion

# Build PAM and NSS modules from source (context is open-bastion/)
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

# Configure PAM for SSH (Mode E: certificate only)
RUN echo '# PAM configuration for SSH Backend with Open Bastion (Mode E)\n\
# Authentication via SSH certificates only (not PAM)\n\
auth       required     pam_permit.so\n\
\n\
# Authorization - check with Open Bastion\n\
account    required     pam_openbastion.so\n\
\n\
# Session - create user if needed, then standard Unix\n\
session    required     pam_openbastion.so create_user=true\n\
session    required     pam_unix.so\n\
' > /etc/pam.d/sshd

# Configure PAM for sudo + sudo -i (Mode E: LLNG temporary token required).
# `sudo -i` uses the separate "sudo-i" PAM service, so it gets the same stack.
RUN echo '# PAM configuration for sudo with Open Bastion (Mode E)\n\
# LLNG temporary token ONLY - Unix passwords REJECTED\n\
auth       sufficient   pam_openbastion.so\n\
auth       required     pam_deny.so\n\
\n\
account    required     pam_openbastion.so\n\
\n\
session    required     pam_unix.so\n\
' | tee /etc/pam.d/sudo /etc/pam.d/sudo-i > /dev/null

# Configure NSS to use Open Bastion
RUN sed -i 's/^passwd:.*/passwd:         files openbastion/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files openbastion/' /etc/nsswitch.conf

# sudo requires PAM authentication (NO NOPASSWD - this is Mode E)
RUN echo "ALL ALL=(ALL:ALL) ALL" >> /etc/sudoers

# Fix PAM loginuid for Docker
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Generate SSH host keys
RUN ssh-keygen -A

# Startup script
COPY docker-demo-maxsec/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
