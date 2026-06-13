#!/bin/bash
# curl shim used only during `ob-builder` generation in the lab. Symlink it as
# `curl` on PATH. It does two things:
#   1. resolves auth.example.com to the libvirt gateway (the host otherwise
#      can't reach the test SSO by that vhost name);
#   2. answers /ssh/ca with a dummy OpenSSH CA — a build-time placeholder that
#      ob-bastion-setup / ob-backend-setup overwrite with the real portal CA at
#      deploy time. The dummy_ca.pub lives next to this script (resolved via
#      readlink so it works through the `curl` symlink).
# Gateway IP is taken from $GW_IP (default 192.168.122.1).
GW="${GW_IP:-192.168.122.1}"
DUMMY_CA="$(dirname "$(readlink -f "$0")")/dummy_ca.pub"
args=("$@")
is_ca=0; outfile=""
i=0
while [ $i -lt ${#args[@]} ]; do
  a="${args[$i]}"
  case "$a" in
    *"/ssh/ca"*) is_ca=1 ;;
    -o) j=$((i+1)); outfile="${args[$j]}" ;;
  esac
  i=$((i+1))
done
if [ "$is_ca" = 1 ]; then
  if [ -n "$outfile" ]; then
    cat "$DUMMY_CA" > "$outfile"
  else
    cat "$DUMMY_CA"
  fi
  exit 0
fi
exec /usr/bin/curl --resolve "auth.example.com:80:$GW" --resolve "auth.example.com:443:$GW" "$@"
