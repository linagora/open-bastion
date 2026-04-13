# Open Bastion SSH Bastion - Maximum Security Mode E
#
# This container provides:
# - SSH certificate authentication ONLY (no authorized_keys)
# - Key Revocation List (KRL) enforcement
# - PAM authorization via Open Bastion
# - sudo via LLNG temporary token only

FROM debian:13-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    sudo \
    nscd \
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
WORKDIR /src/open-bastion
RUN mkdir -p build && cd build && \
    cmake -DBUILD_TESTING=OFF .. && \
    make -j$(nproc) && \
    cp pam_openbastion.so /usr/lib/x86_64-linux-gnu/security/ && \
    cp nss/libnss_openbastion.so.2 /lib/x86_64-linux-gnu/ && \
    cp ../scripts/ob-session-recorder /usr/sbin/ && \
    cp ../scripts/ob-ssh-proxy /usr/bin/ && \
    chmod 755 /usr/sbin/ob-session-recorder && \
    chmod 755 /usr/bin/ob-ssh-proxy && \
    ldconfig && \
    cd / && rm -rf /src/open-bastion/build

# Configure PAM for SSH (Mode E: certificate only, no password)
RUN echo '# PAM configuration for SSH with Open Bastion (Mode E)\n\
# Authentication via SSH certificates only (not PAM)\n\
auth       required     pam_permit.so\n\
\n\
# Authorization - check with Open Bastion\n\
account    required     pam_openbastion.so\n\
\n\
# Session - standard Unix\n\
session    required     pam_unix.so\n\
session    optional     pam_openbastion.so\n\
' > /etc/pam.d/sshd

# Configure PAM for sudo (Mode E: LLNG temporary token required)
RUN echo '# PAM configuration for sudo with Open Bastion (Mode E)\n\
# LLNG temporary token ONLY - Unix passwords REJECTED\n\
auth       sufficient   pam_openbastion.so\n\
auth       required     pam_deny.so\n\
\n\
account    required     pam_openbastion.so\n\
account    required     pam_unix.so\n\
\n\
session    required     pam_unix.so\n\
' > /etc/pam.d/sudo

# sudo requires PAM authentication (NO NOPASSWD - this is Mode E)
RUN echo "ALL ALL=(ALL:ALL) ALL" >> /etc/sudoers

# Fix PAM loginuid for Docker
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Generate SSH host keys
RUN ssh-keygen -A

# Startup script
COPY docker-demo-maxsec/bastion/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
