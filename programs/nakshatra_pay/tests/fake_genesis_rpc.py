#!/usr/bin/env python3
"""Minimal JSON-RPC server used to prove the deployer rejects another genesis."""

import argparse
import json
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    genesis = "NotTheDevnetGenesis111111111111111111111111111"

    def do_POST(self):
        length = int(self.headers.get("Content-Length", "0"))
        request = json.loads(self.rfile.read(length))
        payload = {
            "jsonrpc": "2.0",
            "id": request.get("id"),
            "result": self.genesis,
        }
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *_args):
        return


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--genesis", default=Handler.genesis)
    args = parser.parse_args()
    Handler.genesis = args.genesis
    HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
