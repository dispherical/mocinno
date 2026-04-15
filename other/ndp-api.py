#!/usr/bin/env python3
# must be ran on pve host

import os
import re
import subprocess
from http.server import BaseHTTPRequestHandler, HTTPServer

PREFIX = "2a01:4f9:3081:399c"
API_KEY = os.environ.get("NDP_API_KEY", "")


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        auth = self.headers.get("Authorization", "")
        if auth != f"Bearer {API_KEY}" or not API_KEY:
            self.send_response(403)
            self.end_headers()
            self.wfile.write(b"Forbidden")
            return

        m = re.match(r"/add/(\d+)", self.path)
        if not m:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Bad request")
            return

        vmid = m.group(1)
        try:
            cfg = subprocess.check_output(
                ["pct", "config", vmid], stderr=subprocess.DEVNULL
            ).decode()
            match = re.search(rf"ip6={PREFIX}::([^/,\s]+)", cfg)
            if match:
                addr = f"{PREFIX}::{match.group(1)}"
                subprocess.run(
                    ["ip", "-6", "neigh", "add", "proxy", addr, "dev", "vmbr0"],
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["ip", "-6", "route", "add", f"{addr}/128", "dev", "vmbr4030"],
                    stderr=subprocess.DEVNULL,
                )
                self.send_response(200)
                self.end_headers()
                self.wfile.write(f"Added {addr}".encode())
                return
        except Exception:
            pass

        self.send_response(404)
        self.end_headers()
        self.wfile.write(b"Not found")

    def log_message(self, *args):
        pass


HTTPServer(("0.0.0.0", 9191), Handler).serve_forever()
