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
    nscd \
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
WORKDIR /src/open-bastion
RUN mkdir -p build && cd build && \
    cmake -DBUILD_TESTING=OFF .. && \
    make -j$(nproc) && \
    cp pam_openbastion.so /usr/lib/x86_64-linux-gnu/security/ && \
    cp nss/libnss_openbastion.so.2 /lib/x86_64-linux-gnu/ && \
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

# Configure PAM for sudo (Mode E: LLNG temporary token required)
RUN echo '# PAM configuration for sudo with Open Bastion (Mode E)\n\
# LLNG temporary token ONLY - Unix passwords REJECTED\n\
auth       sufficient   pam_openbastion.so\n\
auth       required     pam_deny.so\n\
\n\
account    required     pam_openbastion.so\n\
\n\
session    required     pam_unix.so\n\
' > /etc/pam.d/sudo

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
