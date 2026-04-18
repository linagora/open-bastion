# Open Bastion Quick Start - Single SSH server with token authentication
#
# Minimal Dockerfile that builds pam_openbastion + libnss_openbastion from source,
# configures PAM/NSS and enrolls itself against LemonLDAP::NG at startup.

FROM debian:13-slim

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

RUN mkdir -p /var/run/sshd \
    /var/cache/open-bastion \
    /etc/open-bastion \
    && chmod 750 /var/cache/open-bastion

# Build PAM and NSS modules (build context is the open-bastion repo root)
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

# Fix PAM loginuid for Docker
RUN sed -i 's/session\s*required\s*pam_loginuid.so/session optional pam_loginuid.so/' /etc/pam.d/sshd 2>/dev/null || true

RUN ssh-keygen -A

COPY quick-start/server/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/sbin/sshd", "-D", "-e"]
