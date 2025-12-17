# LLNG SSH Bastion - Certificate Authentication with Session Recording
#
# This container provides:
# - SSH certificate authentication via LLNG CA
# - Session recording for audit
# - PAM authorization via LLNG

FROM debian:13-slim

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssh-server \
    libcurl4-gnutls-dev \
    libjson-c-dev \
    libssl-dev \
    libpam0g-dev \
    curl \
    jq \
    cmake \
    gcc \
    make \
    bsdutils \
    && rm -rf /var/lib/apt/lists/*

# Create directories
RUN mkdir -p /var/run/sshd \
    /var/cache/pam_llng \
    /var/cache/nss_llng \
    /var/lib/llng-sessions \
    /etc/llng \
    && chmod 700 /var/lib/llng-sessions \
    && chmod 750 /var/cache/pam_llng \
    && chmod 750 /var/cache/nss_llng

# Build PAM module from source (context is llng-pam-module/)
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
    cp ../scripts/llng-session-recorder /usr/sbin/ && \
    chmod 755 /usr/sbin/llng-session-recorder && \
    ldconfig && \
    cd / && rm -rf /src/llng-pam-module/build

# Configure PAM for SSH (bastion mode)
RUN echo '# PAM configuration for SSH Bastion with LemonLDAP::NG\n\
# Authentication via SSH certificates (not PAM)\n\
auth       required     pam_permit.so\n\
\n\
# Authorization - check with LLNG\n\
account    required     pam_llng.so\n\
\n\
# Session - standard Unix\n\
session    required     pam_unix.so\n\
session    optional     pam_llng.so\n\
' > /etc/pam.d/sshd

# Session recorder configuration
RUN echo '# LLNG Session Recorder Configuration\n\
sessions_dir = /var/lib/llng-sessions\n\
format = script\n\
max_duration = 28800\n\
' > /etc/llng/session-recorder.conf

# Fix PAM loginuid for Docker
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Generate SSH host keys
RUN ssh-keygen -A

# Startup script
COPY docker/bastion/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
