#!/bin/bash
# Rebuild and install the Open Bastion LLNG conf (OIDC + pam-access RP).
# Run from any directory; requires: docker, jq, openssl.
# Usage: bash local/sso/configure.sh [--regen-keys]
#
# By default, reuses /tmp/ob_sig.key + /tmp/ob_sig.pub if they already exist.
# Pass --regen-keys to force regeneration of a new keypair.

set -euo pipefail

REGEN_KEYS=0
for arg in "$@"; do
  case "$arg" in
    --regen-keys) REGEN_KEYS=1 ;;
    *) echo "Unknown argument: $arg"; exit 1 ;;
  esac
done

CONTAINER=ob-sso
CONF_DIR=/var/lib/lemonldap-ng/conf
PRIVKEY=/tmp/ob_sig.key
PUBKEY=/tmp/ob_sig.pub
CURCONF=/tmp/lmConf-cur.json
NEWCONF=/tmp/lmConf-new.json

# ── 1. Key generation ────────────────────────────────────────────────────────
if [ "$REGEN_KEYS" = "1" ] || [ ! -f "$PRIVKEY" ] || [ ! -f "$PUBKEY" ]; then
  echo "[1/5] Generating RSA 2048 signing keypair..."
  openssl genrsa -out "$PRIVKEY" 2048 2>/dev/null
  openssl rsa -in "$PRIVKEY" -pubout -out "$PUBKEY" 2>/dev/null
  echo "      Keypair written to $PRIVKEY / $PUBKEY"
else
  echo "[1/5] Reusing existing keypair ($PRIVKEY / $PUBKEY)"
fi

# SSH CA keypair (ed25519, PEM — the SSHCA plugin converts PEM to OpenSSH
# format itself). Used by the cert-vouching flow (/ssh/sign + /pam/bastion-cert).
CA_PRIVKEY=/tmp/ob_sshca.key
CA_PUBKEY=/tmp/ob_sshca.pub
if [ "$REGEN_KEYS" = "1" ] || [ ! -f "$CA_PRIVKEY" ] || [ ! -f "$CA_PUBKEY" ]; then
  echo "[1b/5] Generating ed25519 SSH CA keypair..."
  openssl genpkey -algorithm ed25519 -out "$CA_PRIVKEY" 2>/dev/null
  openssl pkey -in "$CA_PRIVKEY" -pubout -out "$CA_PUBKEY" 2>/dev/null
else
  echo "[1b/5] Reusing existing SSH CA keypair ($CA_PRIVKEY / $CA_PUBKEY)"
fi

# SSH CA state dir (serial counter + KRL) inside the container, owned by the
# portal user. Backed by the ob-sso-ssh volume so it survives recreation.
docker exec "$CONTAINER" sh -c 'mkdir -p /var/lib/lemonldap-ng/ssh && chown www-data:www-data /var/lib/lemonldap-ng/ssh'

# ── 2. Copy current highest-numbered conf ────────────────────────────────────
echo "[2/5] Fetching current active conf from container..."
HIGHEST=$(docker exec "$CONTAINER" ls "$CONF_DIR" \
  | grep -E '^lmConf-[0-9]+\.json$' \
  | sed 's/lmConf-//;s/\.json//' \
  | sort -n | tail -1)
docker cp "${CONTAINER}:${CONF_DIR}/lmConf-${HIGHEST}.json" "$CURCONF"
CUR=$(jq -r .cfgNum "$CURCONF")
NEW=$((CUR + 1))
echo "      Current cfgNum=$CUR, new cfgNum=$NEW"

# ── 3. Build the merged conf ─────────────────────────────────────────────────
echo "[3/5] Building lmConf-${NEW}.json ..."
jq --rawfile priv "$PRIVKEY" \
   --rawfile pub  "$PUBKEY" \
   --rawfile capriv "$CA_PRIVKEY" \
   --rawfile capub  "$CA_PUBKEY" \
   --argjson new  "$NEW" \
   '. + {
     cfgNum: $new,
     cfgLog: "Open Bastion lab: OIDC + pam-access RP",
     issuerDBOpenIDConnectActivation: 1,
     # LAB ACCÉLÉRÉ : session globale 10 min (test du cycle de vie token sans
     # attendre des heures). Voir aussi Access/Offline expiration par RP ci-dessous.
     timeout: 600,
     customPlugins: "::Plugins::PamAccess ::Plugins::OIDCDeviceAuthorization ::Plugins::OIDCDeviceOrganization",
     oidcServiceAllowAuthorizationCodeFlow: 1,
     oidcServiceMetaDataAuthorizeURI: "authorize",
     oidcServiceMetaDataTokenURI: "token",
     oidcServiceMetaDataUserInfoURI: "userinfo",
     oidcServiceMetaDataJWKSURI: "jwks",
     oidcServiceMetaDataIntrospectionURI: "introspect",
     oidcServiceMetaDataEndSessionURI: "logout",
     oidcServiceMetaDataCheckSessionURI: "checksession",
     oidcServiceMetaDataRegistrationURI: "register",
     oidcServicePrivateKeySig: $priv,
     oidcServicePublicKeySig: $pub,
     oidcServiceKeyIdSig: "obkey1",
     oidcRPMetaDataOptions: {
       "pam-access": {
         "oidcRPMetaDataOptionsDisplayName": "PAM Access",
         "oidcRPMetaDataOptionsClientID": "pam-access",
         "oidcRPMetaDataOptionsClientSecret": "pamsecret",
         "oidcRPMetaDataOptionsPublic": 0,
         "oidcRPMetaDataOptionsBypassConsent": 1,
         "oidcRPMetaDataOptionsIDTokenSignAlg": "RS256",
         "oidcRPMetaDataOptionsAccessTokenExpiration": 600,
         "oidcRPMetaDataOptionsAllowDeviceAuthorization": 1,
         "oidcRPMetaDataOptionsAllowOffline": 1,
         "oidcRPMetaDataOptionsOfflineSessionExpiration": 2592000,
         "oidcRPMetaDataOptionsRefreshToken": 0,
         "oidcRPMetaDataOptionsRefreshTokenRotation": 0,
         "oidcRPMetaDataOptionsDeviceOwnership": "organization"
       },
       # Dedicated RP for the bastion: /pam/bastion-cert refuses to trust a
       # caller-claimed server_group, so bastion-ness comes from the client_id
       # via the pamAccessServerGroups map below (bastion_id == client_id).
       "ob-bastion": {
         "oidcRPMetaDataOptionsDisplayName": "Open Bastion (bastion role)",
         "oidcRPMetaDataOptionsClientID": "ob-bastion",
         "oidcRPMetaDataOptionsClientSecret": "bastionsecret",
         "oidcRPMetaDataOptionsPublic": 0,
         "oidcRPMetaDataOptionsBypassConsent": 1,
         "oidcRPMetaDataOptionsIDTokenSignAlg": "RS256",
         "oidcRPMetaDataOptionsAccessTokenExpiration": 600,
         "oidcRPMetaDataOptionsAllowDeviceAuthorization": 1,
         "oidcRPMetaDataOptionsAllowOffline": 1,
         "oidcRPMetaDataOptionsOfflineSessionExpiration": 2592000,
         "oidcRPMetaDataOptionsRefreshToken": 0,
         "oidcRPMetaDataOptionsRefreshTokenRotation": 0,
         "oidcRPMetaDataOptionsDeviceOwnership": "organization"
       }
     },
     oidcRPMetaDataScopeRules: {
       "pam-access": { "pam": "1", "pam:server": "1" },
       "ob-bastion": { "pam": "1", "pam:server": "1" }
     },
     oidcRPMetaDataExportedVars: {
       "pam-access": { "email": "mail", "name": "cn", "groups": "groups" },
       "ob-bastion": { "email": "mail", "name": "cn", "groups": "groups" }
     },
     pamAccessActivation: 1,
     pamAccessRp: "pam-access",
     pamAccessSshRules: { "default": "1" },
     pamAccessExportedVars: { "gecos": "cn" },
     # client_id -> server_group authority map. Without it /pam/bastion-cert
     # resolves every caller to group "default" (it deliberately never trusts
     # a caller-claimed group) and no device can act as a bastion.
     pamAccessServerGroups: { "ob-bastion": "bastion", "pam-access": "backend" },

     # ── Cert-vouching (bastion → backend), plugins PR #30 ──
     # SSHCA autoloads when sshCaActivation=1 (no customPlugins entry needed).
     sshCaActivation: 1,
     sshCaKeyType: "ed25519",
     sshCaKeyRef: "ssh-ca",
     keys: ((.keys // {}) + { "ssh-ca": { keyPrivate: $capriv, keyPublic: $capub, keyComment: "ob-lab-ssh-ca" } }),
     sshCaCertDefaultValidity: 60,
     sshCaCertMaxValidity: 480,
     sshCaPrincipalSources: "$uid",
     sshCaSerialPath: "/var/lib/lemonldap-ng/ssh/serial",
     sshCaKrlPath: "/var/lib/lemonldap-ng/ssh/revoked_keys",
     portalDisplaySshCa: 1,
     # Devices enrolled with server_group "bastion" may vouch (mint vouchers in
     # /pam/authorize and call /pam/bastion-cert). Defaults made explicit:
     pamAccessBastionGroups: "bastion",
     pamAccessBastionVoucherTtl: 43200,
     pamAccessBastionCertTtl: 120
   }' "$CURCONF" > "$NEWCONF"

# Validate
jq . "$NEWCONF" >/dev/null
echo "      JSON valid"

# ── 4. Install into container ────────────────────────────────────────────────
echo "[4/5] Installing lmConf-${NEW}.json into container..."
OWNER=$(docker exec "$CONTAINER" stat -c '%u:%g' "${CONF_DIR}/lmConf-1.json")
MODE=$(docker exec  "$CONTAINER" stat -c '%a'    "${CONF_DIR}/lmConf-1.json")
docker cp "$NEWCONF" "${CONTAINER}:${CONF_DIR}/lmConf-${NEW}.json"
docker exec "$CONTAINER" chown "$OWNER" "${CONF_DIR}/lmConf-${NEW}.json"
docker exec "$CONTAINER" chmod "$MODE"  "${CONF_DIR}/lmConf-${NEW}.json"
echo "      Installed as lmConf-${NEW}.json (owner=$OWNER mode=$MODE)"

# ── 5. Reload and verify ─────────────────────────────────────────────────────
echo "[5/5] Restarting $CONTAINER ..."
docker restart "$CONTAINER" >/dev/null
echo "      Waiting for portal to come up..."
for i in $(seq 1 15); do
  code=$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: auth.example.com' http://127.0.0.1:8090/.well-known/openid-configuration 2>/dev/null || true)
  [ "$code" = "200" ] && break
  sleep 1
done

echo ""
echo "=== Verification ==="

echo ""
echo "-- lemonldap-ng-cli --"
docker exec "$CONTAINER" lemonldap-ng-cli get issuerDBOpenIDConnectActivation customPlugins 2>/dev/null | grep -v CONFIG_GET

echo ""
echo "-- OIDC discovery (issuer + device endpoint) --"
curl -s -H 'Host: auth.example.com' http://127.0.0.1:8090/.well-known/openid-configuration \
  | jq '{issuer, token_endpoint, device_authorization_endpoint}'

echo ""
echo "-- Device flow smoke test --"
curl -s \
  -H 'Host: auth.example.com' \
  -d 'client_id=pam-access&client_secret=pamsecret&scope=pam:server offline_access' \
  http://127.0.0.1:8090/oauth2/device | jq .

echo ""
echo "Done. Config cfgNum=$NEW is active."
