#!/usr/bin/env python3
"""Native proxy acceptance against synthetic, local verifier/application servers."""
import http.client
import http.server
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import threading
import time

ROOT = Path(__file__).resolve().parents[1]
STATE = {"status": 200, "app": [], "verify": []}


class Fixture(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request()

    def handle_request(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        headers = {key.lower(): value for key, value in self.headers.items()}
        event = {"method": self.command, "path": self.path, "headers": headers,
                 "body": body.decode()}
        if self.server.server_port == 9081:
            STATE["verify"].append(event)
            valid = (self.command == "GET" and self.path == "/auth/verify" and not body
                     and self.headers.get_all("Authorization") == ["Bearer fixture-token"])
            status = STATE["status"] if valid else 401
            payload = b""
        else:
            STATE["app"].append(event)
            status = 200
            payload = json.dumps(event).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(payload)))
        # A proxy must not turn arbitrary verifier headers into app authority.
        self.send_header("X-Auth-User-Id", "verifier-fixture")
        self.end_headers()
        self.wfile.write(payload)


def request(headers, method="GET", body=""):
    connection = http.client.HTTPConnection("127.0.0.1", 9080, timeout=4)
    try:
        connection.putrequest(method, "/invoke?fixture=1")
        for name, value in headers:
            connection.putheader(name, value)
        connection.putheader("Content-Length", str(len(body.encode())))
        connection.endheaders(body.encode())
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def main():
    kind = sys.argv[1]
    docker_image = sys.argv[2] if len(sys.argv) == 3 else None
    binary = kind if docker_image else shutil.which(kind)
    if binary is None:
        raise SystemExit(f"Required native binary is unavailable: {kind}")
    config = ROOT / "proxies"
    commands = {
        "nginx": ([binary, "-t", "-c", str(config / "nginx.conf")],
                  [binary, "-c", str(config / "nginx.conf"), "-g", "daemon off;"]),
        "caddy": ([binary, "validate", "--config", str(config / "Caddyfile")],
                  [binary, "run", "--config", str(config / "Caddyfile")]),
        "haproxy": ([binary, "-c", "-f", str(config / "haproxy.cfg")],
                    [binary, "-db", "-f", str(config / "haproxy.cfg")]),
    }
    check, launch = commands[kind]
    if docker_image:
        prefix = ["docker", "run", "--rm", "--network", "host", "--volume",
                  f"{ROOT}:{ROOT}:ro", "--workdir", str(ROOT),
                  "--entrypoint", binary, docker_image]
        check = prefix + check[1:]
        launch = prefix + launch[1:]
    subprocess.run(check, cwd=ROOT, check=True)
    servers = [http.server.ThreadingHTTPServer(("127.0.0.1", port), Fixture)
               for port in [9081, 9082]]
    for server in servers:
        threading.Thread(target=server.serve_forever, daemon=True).start()
    process = subprocess.Popen(launch, cwd=ROOT)
    try:
        for _attempt in range(100):
            if process.poll() is not None:
                raise AssertionError("proxy exited before listening")
            try:
                with socket.create_connection(("127.0.0.1", 9080), timeout=0.05):
                    break
            except OSError:
                time.sleep(0.05)
        else:
            raise AssertionError("proxy did not start")

        valid = [("Authorization", "Bearer fixture-token")]
        denied_headers = [[], [("Authorization", "Basic fixture")],
                          [("Authorization", "Bearer invalid")],
                          valid + [("aUtHoRiZaTiOn", "Bearer invalid")],
                          [("Authorization", "Bearer fixture-token, Bearer invalid")]]
        for headers in denied_headers:
            before = len(STATE["app"])
            status, _body = request(headers)
            assert status >= 400, status
            assert len(STATE["app"]) == before, "denied request reached application"

        spoofed = valid + [("X-Auth-User-Id", "forged"), ("X-Auth-Roles", "admin"),
                           ("X-Shared-Auth-Proof", "forged"), ("Cookie", "fixture=secret"),
                           ("X-Forwarded-User", "forged"), ("Content-Type", "application/json")]
        status, body = request(spoofed, "POST", '{"fixture":true}')
        assert status == 200, status
        application = json.loads(body)
        verifier = STATE["verify"][-1]
        assert "fixture=1" not in json.dumps(verifier), "query leaked to verifier"
        assert application["method"] == "POST" and application["body"] == '{"fixture":true}'
        assert application["path"] == "/invoke?fixture=1"
        assert application["headers"]["authorization"] == "Bearer fixture-token"
        for key in application["headers"]:
            assert not key.startswith(("x-auth-", "x-shared-auth-")), key
            assert key not in ["cookie", "x-forwarded-user"], key

        # Same token must be checked again after revocation: no positive cache.
        for verifier_status in [401, 403, 500, 503, 302]:
            STATE["status"] = verifier_status
            before = len(STATE["app"])
            checks = len(STATE["verify"])
            status, _body = request(valid)
            assert status != 200, (verifier_status, status)
            assert len(STATE["app"]) == before
            assert len(STATE["verify"]) == checks + 1
        servers[0].shutdown()
        servers[0].server_close()
        before = len(STATE["app"])
        assert request(valid)[0] >= 400
        assert len(STATE["app"]) == before
        print(f"{kind}: native auth admission acceptance passed")
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    main()
