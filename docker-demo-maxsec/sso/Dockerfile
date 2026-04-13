# LemonLDAP::NG SSO with pre-initialized server tokens
#
# This extends the standard LLNG portal image to pre-create
# server tokens at startup for bastion and backend.

FROM yadd/lemonldap-ng-portal:latest-non-root

# Create SSH directory for SSHCA plugin (must be done as root during build)
USER root
RUN mkdir -p /var/lib/lemonldap-ng/ssh && chown www-data:www-data /var/lib/lemonldap-ng/ssh
USER www-data

# Copy token initialization script to run during container init
COPY --chmod=755 init-tokens.sh /etc/cont-init.d/10-init-tokens

# Keep original entrypoint and command
