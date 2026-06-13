#!/bin/bash
# Shim: resolve auth.example.com to the libvirt gateway. For /ssh/ca requests
# the LLNG test portal has no sshCa plugin, so synthesize a valid dummy
# OpenSSH CA key (Mode A token-only does not use the CA at runtime). Honour an
# -o OUTFILE if present so callers reading from the output file work.
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
    cat /tmp/obshim/dummy_ca.pub > "$outfile"
  else
    cat /tmp/obshim/dummy_ca.pub
  fi
  exit 0
fi
exec /usr/bin/curl --resolve auth.example.com:80:192.168.122.1 --resolve auth.example.com:443:192.168.122.1 "$@"
