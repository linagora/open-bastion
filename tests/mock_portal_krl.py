#!/usr/bin/env python3
"""A LemonLDAP::NG stand-in serving /ssh/revoked, for tests/test_ob_krl_refresh.sh.

Each MODE is one answer ob-krl-refresh has to survive. Only `krl` is a list
sshd would accept; every other mode must leave the current list untouched,
because sshd treats a revocation list it cannot parse as revoking every key.

  krl        200, the bytes of KRL_FILE
  html       200, the portal's HTML login page (what LLNG serves for a path
             no plugin registered: a 200, not a 404)
  truncated  200, the first 20 bytes of KRL_FILE: a valid header on a body
             that stops short, the case a magic-only check misses
  corrupt    200, KRL_FILE followed by bytes that are no KRL section: good
             header, full length, unparseable tail
  empty      200, no body
  notfound   404
  error      500

Every request path is appended to <KRL_FILE>.log, so a test can tell "the
program did not ask" from "the program ignored the answer".

Usage: mock_portal_krl.py <mode> <port> <KRL_FILE>
"""

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

MODE = sys.argv[1]
PORT = int(sys.argv[2])
KRL_FILE = sys.argv[3]

HTML = b"<!DOCTYPE html>\n<html><body>portal login page</body></html>"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, body, ctype="application/octet-stream"):
        self.send_response(code)
        self.send_header("content-type", ctype)
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        with open(KRL_FILE + ".log", "a") as log:
            log.write(self.path + "\n")
        if self.path != "/ssh/revoked":
            self._send(404, b"not found", "text/plain")
            return
        with open(KRL_FILE, "rb") as f:
            krl = f.read()
        if MODE == "krl":
            self._send(200, krl)
        elif MODE == "html":
            self._send(200, HTML, "text/html")
        elif MODE == "truncated":
            self._send(200, krl[:20])
        elif MODE == "corrupt":
            self._send(200, krl + b"\xff" * 8)
        elif MODE == "empty":
            self._send(200, b"")
        elif MODE == "notfound":
            self._send(404, b"not found", "text/plain")
        else:
            self._send(500, b"error", "text/plain")


HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
