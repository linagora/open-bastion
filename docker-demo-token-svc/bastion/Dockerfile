# Open Bastion SSH Bastion - Token + Service Accounts
#
# This container provides:
# - SSH password authentication using Open Bastion tokens (human users)
# - SSH key authentication for service accounts declared in
#   /etc/open-bastion/service-accounts.conf (ansible, backup, ...)
# - Session recording for audit
# - PAM authorization via Open Bastion

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
    bsdutils \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/run/sshd \
    /var/cache/open-bastion \
    /var/lib/open-bastion/sessions \
    /etc/open-bastion \
    && chmod 700 /var/lib/open-bastion/sessions \
    && chmod 750 /var/cache/open-bastion

# Build PAM module from source (context is open-bastion/)
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
    # ob-service-account-keys is referenced by an absolute path
    # (/usr/local/bin/) in this bastion's sshd_config; keep an explicit
    # install there so AuthorizedKeysCommand keeps resolving.
    install -Dm 0755 ../scripts/ob-service-account-keys /usr/local/bin/ob-service-account-keys && \
    # NSS loader (libc) traditionally searches /lib/x86_64-linux-gnu first.
    # On merged-/usr Debian /lib IS /usr/lib, so the symlink would self-loop.
    # Only create the link when the two directories are genuinely distinct.
    sh -c 'if [ "$(readlink -f /lib/x86_64-linux-gnu)" != "$(readlink -f /usr/lib/x86_64-linux-gnu)" ]; then ln -sf /usr/lib/x86_64-linux-gnu/libnss_openbastion.so.2 /lib/x86_64-linux-gnu/libnss_openbastion.so.2; fi' && \
    ldconfig && \
    cd / && rm -rf /src/open-bastion/build

# Configure PAM for SSH (bastion mode with token authentication)
RUN echo '# PAM configuration for SSH Bastion with Open Bastion\n\
# Authentication via Open Bastion tokens (user pastes token as password)\n\
auth       required     pam_openbastion.so\n\
\n\
# Authorization - check with Open Bastion\n\
account    required     pam_openbastion.so\n\
\n\
# Session - standard Unix\n\
session    required     pam_unix.so\n\
session    optional     pam_openbastion.so\n\
' > /etc/pam.d/sshd

# Configure PAM for sudo (Open Bastion authorization)
RUN echo '# PAM configuration for sudo with Open Bastion\n\
auth       required     pam_openbastion.so service_type=sudo\n\
account    required     pam_openbastion.so service_type=sudo\n\
session    required     pam_unix.so\n\
' > /etc/pam.d/sudo

# Sudo requires PAM authentication (no NOPASSWD)
RUN echo "ALL ALL=(ALL:ALL) ALL" >> /etc/sudoers

# Session recorder configuration
RUN echo '# Open Bastion Session Recorder Configuration\n\
sessions_dir = /var/lib/open-bastion/sessions\n\
format = script\n\
max_duration = 28800\n\
' > /etc/open-bastion/session-recorder.conf

# Fix PAM loginuid for Docker
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Generate SSH host keys
RUN ssh-keygen -A

# Startup script
COPY docker-demo-token-svc/bastion/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
