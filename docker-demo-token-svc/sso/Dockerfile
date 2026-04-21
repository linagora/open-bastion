# LemonLDAP::NG SSO with pre-initialized server tokens
#
# This extends the standard LLNG portal image to pre-create
# server tokens at startup for bastion and backend.

FROM yadd/lemonldap-ng-portal:latest-non-root

# Copy token initialization script to run during container init
COPY --chmod=755 init-tokens.sh /etc/cont-init.d/10-init-tokens

# Keep original entrypoint and command
