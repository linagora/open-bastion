#!/usr/bin/env python3
"""Mock LLNG portal that signs its /pam/* answers, for the shell callers (#339).

Usage: mock_portal_signed.py PORT CONTROLFILE LOGFILE SIGNER

The shell twin of tests/mock_portal.h. CONTROLFILE is a JSON object, re-read
on every request so that a test can change the portal's behaviour between two
runs of a script:

    kind           "plain" (application/json), "signed" (a compact JWS bound
                   to the request received) or "replay" (the previous answer,
                   byte for byte)
    status         HTTP status on the wire (default 200)
    resp           the answer object (default: a success for the endpoint)
    key, alg, kid  signing key (PEM file), algorithm and kid
    iss            issuer claim
    aud            audience claim; null leaves it out
    endpoint       endpoint claim (default: the path after /pam/)
    nonce          req_nonce claim (default: the X-Nonce received)
    signed_body    body hashed into req_sha256 (default: the body received)
    signed_status  http_status claim (default: status)
    jwks           the `jwks` claim, any JSON value; absent: no claim
    exp_offset     exp - now (default 60)

Signing is done by SIGNER (tests/jws-sign-fixture, built from
tests/jws_test_util.h), never by the code under test. Every request is
appended to LOGFILE as one JSON object: path, Accept, the X-Nonce headers,
the request-signing headers and the body, so that a test can assert on what
the portal saw.
"""

import hashlib
import json
import subprocess
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = int(sys.argv[1])
CONTROL = sys.argv[2]
LOGFILE = sys.argv[3]
SIGNER = sys.argv[4]

DEFAULT_RESP = {
    "heartbeat": {
        "status": "ok",
        "access_token": "fresh-access-token",
        "expires_in": 3600,
        "next_heartbeat": 300,
    },
    "userinfo": {"found": True, "user": "alice", "uid": 10001},
    "whoami": {"bastion_id": "9f86d081"},
}

LAST = {"raw": b"", "ctype": "application/json", "status": 500}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        with open(CONTROL) as fh:
            ctl = json.load(fh)
        nonces = self.headers.get_all("X-Nonce") or []
        with open(LOGFILE, "a") as fh:
            fh.write(json.dumps({
                "path": self.path,
                "accept": self.headers.get("Accept", ""),
                "nonces": nonces,
                "signature": self.headers.get("X-Signature-256", ""),
                "body": body.decode("utf-8", "replace"),
            }) + "\n")

        endpoint = self.path.rsplit("/", 1)[-1]
        status = ctl.get("status", 200)
        resp = ctl.get("resp", DEFAULT_RESP.get(endpoint, {}))
        kind = ctl.get("kind", "plain")

        if kind == "replay":
            raw, ctype, status = LAST["raw"], LAST["ctype"], LAST["status"]
        elif kind == "signed":
            now = int(time.time())
            claims = {
                "iss": ctl["iss"],
                "iat": now,
                "exp": now + ctl.get("exp_offset", 60),
                "endpoint": ctl.get("endpoint", endpoint),
                "req_sha256": hashlib.sha256(
                    ctl["signed_body"].encode() if "signed_body" in ctl else body
                ).hexdigest(),
                "http_status": ctl.get("signed_status", status),
                "resp": resp,
            }
            if ctl.get("aud") is not None:
                claims["aud"] = ctl["aud"]
            nonce = ctl.get("nonce", nonces[0] if nonces else None)
            if nonce is not None:
                claims["req_nonce"] = nonce
            if "jwks" in ctl:
                claims["jwks"] = ctl["jwks"]
            raw = subprocess.run(
                [SIGNER, "sign", ctl["key"], ctl.get("alg", "ES256"), ctl["kid"]],
                input=json.dumps(claims).encode(),
                stdout=subprocess.PIPE,
                check=True,
            ).stdout
            ctype = "application/ob-pam-response+jwt"
        else:
            raw = json.dumps(resp).encode()
            ctype = "application/json"

        ctype = ctl.get("content_type", ctype)
        LAST.update(raw=raw, ctype=ctype, status=status)
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
