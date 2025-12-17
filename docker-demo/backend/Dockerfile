# LLNG SSH Backend - Certificate Authentication with User Creation
#
# This container provides:
# - SSH certificate authentication via LLNG CA
# - Automatic user creation from LLNG attributes
# - NSS module for user/group resolution
# - Sudo authorization via LLNG

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

# Build PAM and NSS modules from source (context is llng-pam-module/)
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
    ldconfig && \
    cd / && rm -rf /src/llng-pam-module/build

# Configure PAM for SSH (backend mode with user creation)
RUN echo '# PAM configuration for SSH Backend with LemonLDAP::NG\n\
# Authentication via SSH certificates (not PAM)\n\
auth       required     pam_permit.so\n\
\n\
# Authorization - check with LLNG\n\
account    required     pam_llng.so\n\
\n\
# Session - create user if needed, then standard Unix\n\
session    required     pam_llng.so create_user=true\n\
session    required     pam_unix.so\n\
' > /etc/pam.d/sshd

# Configure PAM for sudo (LLNG authorization)
RUN echo '# PAM configuration for sudo with LemonLDAP::NG\n\
auth       required     pam_llng.so service_type=sudo\n\
account    required     pam_llng.so service_type=sudo\n\
session    required     pam_unix.so\n\
' > /etc/pam.d/sudo

# Configure NSS to use LLNG for passwd/group resolution
RUN sed -i 's/^passwd:.*/passwd:         files llng/' /etc/nsswitch.conf && \
    sed -i 's/^group:.*/group:          files llng/' /etc/nsswitch.conf

# Allow all users to sudo (PAM handles authorization)
RUN echo "ALL ALL=(ALL:ALL) NOPASSWD: ALL" >> /etc/sudoers

# Fix PAM loginuid for Docker
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

# Generate SSH host keys
RUN ssh-keygen -A

# Startup script
COPY docker/backend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
