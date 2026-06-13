#!/bin/bash
# LAB shim (deployed to /usr/local/sbin/curl during ob-*-setup): answer GET
# requests to .../ssh/ca with the role's deployed CA key, and pass every other
# request through to the real curl unchanged. The test LLNG portal has no
# sshCa plugin, so this lets ob-bastion-setup / ob-backend-setup complete in
# Mode A (token-only), where the SSH CA is not used at runtime. Token
# enrollment and ob-heartbeat refresh (POST /oauth2/token) are untouched.
_ca=0
_out=""
_args=("$@")
_i=0
while [ "$_i" -lt "${#_args[@]}" ]; do
  _a="${_args[$_i]}"
  case "$_a" in
    */ssh/ca|*/ssh/ca\?*) _ca=1 ;;
    -o) _j=$((_i + 1)); _out="${_args[$_j]}" ;;
  esac
  _i=$((_i + 1))
done
if [ "$_ca" = 1 ]; then
  if [ -n "$_out" ]; then
    cat /etc/ssh/open-bastion_ca.pub > "$_out"
  else
    cat /etc/ssh/open-bastion_ca.pub
  fi
  exit 0
fi
exec /usr/bin/curl "$@"
