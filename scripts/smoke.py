"""End to end smoke test of a freshly started daemon.

Exercises every capability over the real API: proxying, HTTP/2, the site map,
the repeater, the fuzzer, the scanner, the plugin tools and interactive
interception.
"""

from __future__ import annotations

import hashlib
import http.server
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import httpx
import websockets

REPO = Path(__file__).resolve().parent.parent
HOME = Path(tempfile.mkdtemp(prefix="intercept-smoke-"))
PROXY_PORT = 8391
API_PORT = 9391
ORIGIN_PORT = 8392
H2_ORIGIN_PORT = 8393

PAGES = {
    "/": b'<html><a href="/one">one</a><a href="/two">two</a></html>',
    "/one": b'<html><a href="/deep">deep</a></html>',
    "/two": b"<html>two</html>",
    "/deep": b"<html>deep</html>",
}


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _send(self, body: bytes) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        self._send(PAGES.get(self.path, b"<html>missing</html>"))

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        payload = self.rfile.read(length)
        self._send(json.dumps({"echo": payload.decode()}).encode())

    def log_message(self, *args) -> None:
        return


class H2Origin:
    """A tiny HTTP/2 origin server used for the HTTP/2 checks."""

    def __init__(self, cert_path: Path, key_path: Path) -> None:
        import socketserver

        from h2.config import H2Configuration
        from h2.connection import H2Connection

        self._H2Configuration = H2Configuration
        self._H2Connection = H2Connection
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(str(cert_path), str(key_path))
        self.context.set_alpn_protocols(["h2", "http/1.1"])
        self.requests: list[dict] = []
        outer = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                conn = H2Connection(config=H2Configuration(client_side=False))
                conn.initiate_connection()
                self.request.sendall(conn.data_to_send())
                while True:
                    try:
                        data = self.request.recv(65536)
                    except OSError:
                        return
                    if not data:
                        return
                    for event in conn.receive_data(data):
                        name = event.__class__.__name__
                        if name == "RequestReceived":
                            outer.requests.append(
                                {k.decode(): v.decode() for k, v in event.headers}
                            )
                        elif name == "DataReceived":
                            conn.acknowledge_received_data(
                                event.flow_controlled_length, event.stream_id
                            )
                        elif name == "StreamEnded":
                            path = outer.requests[-1].get(":path", "/") if outer.requests else "/"
                            payload = f"hello {path}".encode()
                            conn.send_headers(
                                event.stream_id,
                                [
                                    (b":status", b"200"),
                                    (b"content-type", b"text/plain"),
                                    (b"content-length", str(len(payload)).encode()),
                                    (b"x-origin-server", b"intercept-smoke"),
                                ],
                            )
                            conn.send_data(event.stream_id, payload, end_stream=True)
                    outbound = conn.data_to_send()
                    if outbound:
                        self.request.sendall(outbound)

        class Server(socketserver.ThreadingTCPServer):
            allow_reuse_address = True
            daemon_threads = True

        self.server = Server(("127.0.0.1", H2_ORIGIN_PORT), Handler)
        self.server.socket = self.context.wrap_socket(self.server.socket, server_side=True)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()
            self.server = None


def self_signed_cert(directory: Path, hostname: str = "localhost") -> tuple[Path, Path]:
    """Create a throwaway certificate for the local test origin."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hostname)])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(hostname)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path = directory / "origin.crt"
    key_path = directory / "origin.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def h2_request(proxy_port: int, ca_file: str, host: str, port: int, path: str) -> dict:
    """Send one HTTP/2 request through the proxy and return the result."""
    import asyncio

    from h2.config import H2Configuration
    from h2.connection import H2Connection

    async def run() -> dict:
        reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
        writer.write(
            f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
        )
        await writer.drain()
        await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        context = ssl.create_default_context(cafile=ca_file)
        context.set_alpn_protocols(["h2"])
        await writer.start_tls(context, server_hostname=host)

        conn = H2Connection(config=H2Configuration(client_side=True))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()
        conn.send_headers(
            1,
            [
                (b":method", b"GET"),
                (b":path", path.encode()),
                (b":scheme", b"https"),
                (b":authority", f"{host}:{port}".encode()),
            ],
            end_stream=True,
        )
        writer.write(conn.data_to_send())
        await writer.drain()

        status = 0
        body = b""
        ended = False
        deadline = time.time() + 15
        while time.time() < deadline and not ended:
            data = await asyncio.wait_for(reader.read(65536), timeout=10)
            if not data:
                break
            for event in conn.receive_data(data):
                name = event.__class__.__name__
                if name == "ResponseReceived":
                    status = int(dict(event.headers)[b":status"])
                elif name == "DataReceived":
                    body += event.data
                elif name == "StreamEnded":
                    ended = True
        writer.close()
        return {"status": status, "body": body.decode("utf-8", "replace")}

    return asyncio.run(run())


def check(label: str, condition: bool, detail: str = "") -> None:
    mark = "PASS" if condition else "FAIL"
    print(f"[{mark}] {label}{(' - ' + detail) if detail else ''}")
    if not condition:
        check.failures += 1


check.failures = 0


def main() -> int:
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", ORIGIN_PORT), Handler)
    threading.Thread(target=origin.serve_forever, daemon=True).start()

    cert_path, key_path = self_signed_cert(HOME)
    h2_origin = H2Origin(cert_path, key_path)

    env = {**os.environ, "PYTHONPATH": str(REPO / "src"), "INTERCEPT_HOME": str(HOME)}
    daemon = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "intercept",
            "serve",
            "--port",
            str(PROXY_PORT),
            "--api-port",
            str(API_PORT),
            "--home",
            str(HOME),
            "--insecure",
        ],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    api = f"http://127.0.0.1:{API_PORT}"
    proxy = f"http://127.0.0.1:{PROXY_PORT}"

    try:
        # wait for the daemon
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                httpx.get(f"{api}/api/health", timeout=1)
                break
            except Exception:
                time.sleep(0.2)
        else:
            print("daemon did not start")
            return 1

        health = httpx.get(f"{api}/api/health", timeout=5).json()
        check("daemon is healthy", health["status"] == "ok")

        # ---- proxying -------------------------------------------------
        with httpx.Client(proxy=proxy, timeout=10) as client:
            r = client.get(f"http://127.0.0.1:{ORIGIN_PORT}/one")
            check("request is forwarded", r.status_code == 200 and b"deep" in r.content)
            r = client.post(f"http://127.0.0.1:{ORIGIN_PORT}/post", json={"a": 1})
            check("post body is forwarded", b'"echo"' in r.content)

        time.sleep(0.4)
        traffic = httpx.get(f"{api}/api/traffic", timeout=5).json()
        check("traffic is recorded", len(traffic["items"]) == 2, f"{len(traffic['items'])} entries")
        raws = []
        for item in traffic["items"]:
            body = httpx.get(f"{api}/api/traffic/{item['id']}", timeout=5).json()
            raws.append(body["request"]["raw"])
        check(
            "raw request is preserved",
            any(raw.startswith("GET http://") for raw in raws),
            str(raws)[:120],
        )
        check(
            "raw response is preserved",
            any(
                httpx.get(f"{api}/api/traffic/{i['id']}", timeout=5)
                .json()["response"]["raw"]
                .startswith("HTTP/1.1 200")
                for i in traffic["items"]
            ),
        )

        # ---- site map --------------------------------------------------
        sites = httpx.get(f"{api}/api/sites", timeout=5).json()
        hosts = [h["host"] for h in sites["tree"]]
        check("site map lists the host", "127.0.0.1" in hosts, str(hosts))

        httpx.post(
            f"{api}/api/scope/rules",
            json={"pattern": "127.0.0.1", "kind": "include", "target": "host"},
            timeout=5,
        )
        scope = httpx.get(f"{api}/api/scope", timeout=5).json()
        check("scope rule is stored", len(scope["rules"]) == 1)

        # ---- spider ----------------------------------------------------
        httpx.post(
            f"{api}/api/spider/start",
            json={"seeds": [f"http://127.0.0.1:{ORIGIN_PORT}/"], "use_known_hosts": False},
            timeout=10,
        ).json()
        for _ in range(100):
            time.sleep(0.1)
            state = httpx.get(f"{api}/api/spider/jobs", timeout=5).json()["jobs"]
            if state and state[0]["state"] != "running":
                break
        check("spider crawled the site", state[0]["crawled"] >= 3, f"{state[0]['crawled']} pages")
        check(
            "spider followed links",
            any("/deep" in url for url in state[0]["found"]),
        )

        # ---- repeater --------------------------------------------------
        tab = httpx.post(
            f"{api}/api/repeater/tabs",
            json={
                "method": "POST",
                "url": f"http://127.0.0.1:{ORIGIN_PORT}/repeat",
                "headers": {"Content-Type": ["application/json"]},
                "body": '{"edited": true}',
            },
            timeout=5,
        ).json()
        sent = httpx.post(
            f"{api}/api/repeater/tabs/{tab['id']}/send", json={"tab_id": tab["id"]}, timeout=10
        ).json()
        check("repeater sends an edited request", sent["response"]["status"] == 200)
        check("repeater response has the body", b"edited" in sent["response"]["raw"].encode())

        # ---- plugin tools ----------------------------------------------
        plugins = httpx.get(f"{api}/api/plugins", timeout=5).json()
        check("example plugin is loaded", len(plugins["plugins"]) >= 1)
        check("plugin registers a tool", len(plugins["tools"]) >= 1)
        tool = plugins["tools"][0]
        result = httpx.post(
            f"{api}/api/tools/{tool['id']}/run",
            json={"values": {"value": "a b", "mode": "encode", "encoding": "url"}},
            timeout=5,
        ).json()
        check("plugin tool runs", result.get("output") == "a%20b", str(result))

        # ---- interactive interception ----------------------------------
        httpx.post(f"{api}/api/intercept/toggle", json={"enabled": True}, timeout=5)
        held: list[str] = []

        def answer() -> None:
            for _ in range(100):
                time.sleep(0.05)
                pending = httpx.get(f"{api}/api/intercept", timeout=5).json()["pending"]
                if pending:
                    held.extend(pending)
                    httpx.post(
                        f"{api}/api/intercept/{pending[0]}",
                        json={"action": "forward"},
                        timeout=5,
                    )
                    return

        responder = threading.Thread(target=answer, daemon=True)
        responder.start()
        with httpx.Client(proxy=proxy, timeout=15) as client:
            r = client.get(f"http://127.0.0.1:{ORIGIN_PORT}/held")
        responder.join(timeout=5)
        check("request was held", len(held) == 1, str(held))
        check("held request was forwarded", r.status_code == 200)

        httpx.post(f"{api}/api/intercept/toggle", json={"enabled": False}, timeout=5)

        # ---- fuzzer ----------------------------------------------------
        fuzz = httpx.post(
            f"{api}/api/fuzz/jobs",
            json={
                "method": "GET",
                "url": f"http://127.0.0.1:{ORIGIN_PORT}/fuzz?q=§term§",
                "payloads": ["one", "two"],
                "start": False,
            },
            timeout=5,
        ).json()
        check("fuzz job marks one position", len(fuzz["template"]["positions"]) == 1)
        check("fuzz job knows its size", fuzz["total"] == 2, str(fuzz["total"]))
        started = httpx.post(f"{api}/api/fuzz/jobs/{fuzz['id']}/start", json={}, timeout=5)
        check("fuzz job starts", started.status_code == 200)
        for _ in range(100):
            time.sleep(0.1)
            state = httpx.get(f"{api}/api/fuzz/jobs", timeout=5).json()["jobs"]
            if state and state[0]["status"] not in ("running", "pending"):
                break
        check("fuzz job finished", state[0]["status"] == "finished", state[0]["status"])
        check("fuzz job sent every payload", len(state[0]["results"]) == 2)
        check(
            "fuzz results are recorded as traffic",
            len(httpx.get(f"{api}/api/traffic?origin=fuzzer", timeout=5).json()["items"]) == 2,
        )

        # ---- scanner ---------------------------------------------------
        checks = httpx.get(f"{api}/api/scanner/checks", timeout=5).json()["checks"]
        check("scanner publishes its checks", len(checks) >= 8, f"{len(checks)} checks")
        check(
            "scanner has an active and a passive check",
            {c["kind"] for c in checks} == {"active", "passive"},
        )
        scan = httpx.post(
            f"{api}/api/scanner/jobs",
            json={
                "targets": [f"http://127.0.0.1:{ORIGIN_PORT}/"],
                "checks": ["info.banner", "headers.security"],
                "start": False,
            },
            timeout=5,
        ).json()
        check("scan job knows its size", scan["total"] == 2, str(scan["total"]))
        httpx.post(f"{api}/api/scanner/jobs/{scan['id']}/start", json={}, timeout=5)
        for _ in range(150):
            time.sleep(0.1)
            state = httpx.get(f"{api}/api/scanner/jobs", timeout=5).json()["jobs"]
            if state and state[0]["status"] not in ("running", "pending"):
                break
        check("scan job finished", state[0]["status"] == "finished", state[0]["status"])
        check("scan job ran both checks", len(state[0]["results"]) == 2)
        findings = httpx.get(f"{api}/api/findings", timeout=5).json()
        check("findings are stored", findings["total"] >= 1, f"{findings['total']} findings")
        check(
            "missing security headers are reported",
            any(f["check_id"] == "headers.security" for f in findings["items"]),
            str([f["check_id"] for f in findings["items"]]),
        )

        # ---- comparer --------------------------------------------------
        kinds = httpx.get(f"{api}/api/comparer/kinds", timeout=5).json()
        check(
            "the comparer publishes its kinds",
            len(kinds["kinds"]) >= 8,
            str(len(kinds["kinds"])),
        )
        compared = httpx.post(
            f"{api}/api/comparer/compare",
            json={
                "left": '{"user":"ann","role":"admin"}',
                "right": '{"user":"ann","role":"guest"}',
                "kind": "json",
            },
            timeout=5,
        ).json()
        check(
            "the comparer finds the difference",
            any(difference["path"] == "role" for difference in compared["differences"]),
            str(compared["differences"]),
        )
        check(
            "the comparer finds what is the same",
            any(similarity["path"] == "user" for similarity in compared["similarities"]),
            str(compared["similarities"]),
        )
        check("the comparer puts the two next to each other", len(compared["rows"]) == 1)
        exchanged = httpx.post(
            f"{api}/api/comparer/exchanges",
            json={"left_id": "nope", "right_id": "nope", "part": "response"},
            timeout=5,
        )
        check("the comparer reports an exchange that is not there", exchanged.status_code == 404)

        # ---- decoder ---------------------------------------------------
        kinds = httpx.get(f"{api}/api/decoder/kinds", timeout=5).json()
        check(
            "the decoder publishes its kinds",
            len(kinds["kinds"]) >= 12,
            str(len(kinds["kinds"])),
        )
        converted = httpx.post(
            f"{api}/api/decoder/convert",
            json={"value": "aGVsbG8gd29ybGQ=", "kind": "base64", "mode": "decode"},
            timeout=5,
        ).json()
        check(
            "the decoder decodes base64",
            converted["output"] == "hello world",
            converted["output"],
        )
        chained = httpx.post(
            f"{api}/api/decoder/chain",
            json={
                "value": "aGVsbG8gd29ybGQ=",
                "steps": [
                    {"kind": "base64", "mode": "decode"},
                    {"kind": "url", "mode": "decode"},
                ],
            },
            timeout=5,
        ).json()
        check("the decoder runs a chain", chained["output"] == "hello world", chained["output"])
        smart = httpx.post(
            f"{api}/api/decoder/smart",
            json={"value": "aGVsbG8gd29ybGQ="},
            timeout=5,
        ).json()
        check(
            "the smart decode finds the encoding",
            smart["best"]["kind"] == "base64",
            str(smart["best"]),
        )
        digest = httpx.post(
            f"{api}/api/decoder/hash",
            json={"value": "hello", "algorithm": "sha256"},
            timeout=5,
        ).json()
        check(
            "the decoder makes a digest",
            digest["output"] == hashlib.sha256(b"hello").hexdigest(),
            digest["output"],
        )

        # ---- sequencer --------------------------------------------------
        report = httpx.post(
            f"{api}/api/sequencer/analyze",
            json={"samples": [f"token-{index}" for index in range(20)], "kind": "auto"},
            timeout=5,
        ).json()
        check("the sequencer measures the samples", report["samples"] == 20, str(report["samples"]))
        check(
            "the sequencer calls a counter predictable",
            report["verdict"] == "predictable",
            report["verdict"],
        )

        # ---- workspace -------------------------------------------------
        commands = httpx.get(f"{api}/api/commands", timeout=5).json()
        check("commands are listed", len(commands["commands"]) > 10, str(len(commands["commands"])))
        found = httpx.get(f"{api}/api/commands/search", params={"q": "clear"}, timeout=5).json()
        check("commands can be searched", len(found["commands"]) > 0)
        run = httpx.post(f"{api}/api/commands/traffic.clear/run", json={"args": {}}, timeout=5)
        check("a command runs", run.status_code == 200, str(run.status_code))

        httpx.put(f"{api}/api/filter", json={"filter": "status >= 400"}, timeout=5)
        check(
            "the filter is stored",
            httpx.get(f"{api}/api/filter", timeout=5).json()["expression"] == "status >= 400",
        )
        broken = httpx.put(f"{api}/api/filter", json={"filter": "nope == 1"}, timeout=5)
        check("a broken filter is rejected", broken.status_code == 400)
        httpx.put(f"{api}/api/filter", json={"filter": ""}, timeout=5)

        note = httpx.post(
            f"{api}/api/notes",
            json={"subject": "exchange", "subject_id": "abc", "text": "look at this"},
            timeout=5,
        ).json()
        check("a note is stored", note["text"] == "look at this")
        updated_note = httpx.put(
            f"{api}/api/notes/{note['id']}", json={"text": "looked"}, timeout=5
        )
        check("a note is updated", updated_note.json()["text"] == "looked")

        issue = httpx.post(
            f"{api}/api/issues", json={"title": "Open redirect", "severity": "high"}, timeout=5
        ).json()
        check("an issue is raised", issue["status"] == "open")
        moved = httpx.put(
            f"{api}/api/issues/{issue['id']}", json={"status": "resolved"}, timeout=5
        )
        check("an issue is resolved", moved.json()["status"] == "resolved")
        check(
            "a partial update keeps the other fields",
            moved.json()["title"] == "Open redirect" and moved.json()["severity"] == "high",
            str(moved.json()),
        )

        target = httpx.post(
            f"{api}/api/targets",
            json={"name": "Example", "host": "example.com", "port": 8443},
            timeout=5,
        ).json()
        check("a target is recorded", target["port"] == 8443)
        scoped = httpx.put(f"{api}/api/targets/{target['id']}", json={"in_scope": False}, timeout=5)
        check("a target goes out of scope", scoped.json()["in_scope"] is False)
        check(
            "a partial target update keeps the port",
            scoped.json()["port"] == 8443 and scoped.json()["name"] == "Example",
            str(scoped.json()),
        )

        task = httpx.post(
            f"{api}/api/tasks",
            json={"name": "Crawl", "command": "spider.crawl", "interval": 30},
            timeout=5,
        ).json()
        check("a task is scheduled", task["command"] == "spider.crawl")
        check(
            "a task can be run now",
            httpx.post(f"{api}/api/tasks/{task['id']}/run", timeout=5).status_code == 200,
        )

        project = httpx.post(f"{api}/api/projects", json={"name": "Engagement"}, timeout=5).json()
        check("a project is created", project["name"] == "Engagement")
        check(
            "a project is saved",
            httpx.post(f"{api}/api/projects/{project['id']}/save", timeout=10).status_code == 200,
        )

        report = httpx.get(f"{api}/api/reports", timeout=5).json()
        check("a report is built", "summary" in report)
        rendered = httpx.get(f"{api}/api/reports/render", params={"format": "markdown"}, timeout=5)
        check("a report is rendered", rendered.text.startswith("# "), rendered.text[:40])

        organizer = httpx.get(f"{api}/api/organizer", timeout=5).json()
        check("the organizer groups the traffic", "hosts" in organizer)

        dashboard = httpx.get(f"{api}/api/dashboard", timeout=5).json()
        check("the dashboard is built", "traffic" in dashboard and "issues" in dashboard)

        sockets = httpx.get(f"{api}/api/websockets/connections", timeout=5).json()
        check("the websocket history is served", "connections" in sockets)

        # ---- HTTP/2 ----------------------------------------------------
        ca_file = str(HOME / "ca" / "root.crt")
        if Path(ca_file).exists():
            h2 = h2_request(PROXY_PORT, ca_file, "localhost", H2_ORIGIN_PORT, "/h2")
            check("http/2 request is answered", h2["status"] == 200, str(h2))
            check("http/2 body is delivered", "hello /h2" in h2["body"], h2["body"][:60])
            time.sleep(0.4)
            h2_traffic = [
                item
                for item in httpx.get(f"{api}/api/traffic", timeout=5).json()["items"]
                if item.get("http_version") == "HTTP/2"
            ]
            check("http/2 traffic is recorded", len(h2_traffic) == 1, str(len(h2_traffic)))
        else:
            check("http/2 request is answered", False, "no CA certificate to trust")

        # ---- event stream ----------------------------------------------
        async def watch() -> bool:

            async with websockets.connect(f"ws://127.0.0.1:{API_PORT}/ws") as socket:
                await asyncio_wait(socket.recv())
                with httpx.Client(proxy=proxy, timeout=10) as client:
                    client.get(f"http://127.0.0.1:{ORIGIN_PORT}/stream")
                for _ in range(20):
                    message = json.loads(await asyncio_wait(socket.recv()))
                    if message["type"] == "response":
                        return True
            return False

        import asyncio

        async def asyncio_wait(awaitable):
            return await asyncio.wait_for(awaitable, timeout=10)

        streamed = asyncio.run(watch())
        check("event stream reports new traffic", streamed)

    finally:
        daemon.terminate()
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
        origin.shutdown()
        h2_origin.stop()
        shutil.rmtree(HOME, ignore_errors=True)

    print()
    if check.failures:
        print(f"{check.failures} check(s) failed")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
