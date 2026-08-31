#!/usr/bin/env python3
"""Deterministic loopback protocol spike for the WP-13 proxy contract."""

from __future__ import annotations

import argparse
import ipaddress
import json
import socket
import struct
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable
from urllib.parse import unquote, urlsplit


@dataclass
class CaseResult:
    name: str
    status: str
    detail: str


@dataclass(frozen=True)
class ProxyDecision:
    source: str
    scheme: str
    endpoint_family: str
    authenticated: bool


def recv_exact(conn: socket.socket, size: int) -> bytes:
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise EOFError(f"expected {size} bytes, received {len(data)}")
        data.extend(chunk)
    return bytes(data)


def recv_until(conn: socket.socket, marker: bytes, limit: int = 8192) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = conn.recv(1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > limit:
            raise ValueError("proxy request exceeds test limit")
    return bytes(data)


def recv_cstring(conn: socket.socket, limit: int = 255) -> bytes:
    data = bytearray()
    while len(data) <= limit:
        value = recv_exact(conn, 1)
        if value == b"\x00":
            return bytes(data)
        data.extend(value)
    raise ValueError("SOCKS4 string exceeds test limit")


class OneShotProxy:
    def __init__(self, handler: Callable[[socket.socket], None]) -> None:
        self._handler = handler
        self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listener.bind(("127.0.0.1", 0))
        self._listener.listen(1)
        self.port = int(self._listener.getsockname()[1])
        self.error: BaseException | None = None
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        try:
            conn, _ = self._listener.accept()
            with conn:
                conn.settimeout(2)
                self._handler(conn)
        except BaseException as exc:  # Captured and re-raised in the test thread.
            self.error = exc
        finally:
            self._listener.close()

    def __enter__(self) -> OneShotProxy:
        self._thread.start()
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self._thread.join(timeout=3)
        if self._thread.is_alive():
            raise TimeoutError("fake proxy did not terminate")
        if self.error is not None:
            raise self.error


def connect_local(port: int) -> socket.socket:
    conn = socket.create_connection(("127.0.0.1", port), timeout=2)
    conn.settimeout(2)
    return conn


def format_connect_authority(host: str, port: int) -> str:
    try:
        parsed = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    if parsed.version == 6:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def http_connect(port: int, host: str, target_port: int) -> int:
    authority = format_connect_authority(host, target_port)
    request = (
        f"CONNECT {authority} HTTP/1.1\r\n"
        f"Host: {authority}\r\n"
        "Proxy-Connection: keep-alive\r\n\r\n"
    ).encode("ascii")
    with connect_local(port) as conn:
        conn.sendall(request)
        status_line = recv_until(conn, b"\r\n").split(b"\r\n", 1)[0]
    fields = status_line.split(b" ", 2)
    if len(fields) < 2 or fields[0] != b"HTTP/1.1":
        raise ValueError("malformed HTTP proxy response")
    return int(fields[1])


def http_handler(expected_authority: str, status: int) -> Callable[[socket.socket], None]:
    def handle(conn: socket.socket) -> None:
        request = recv_until(conn, b"\r\n\r\n").decode("ascii")
        lines = request.split("\r\n")
        expected_line = f"CONNECT {expected_authority} HTTP/1.1"
        if not lines or lines[0] != expected_line:
            raise AssertionError(f"unexpected request line: {lines[0] if lines else ''}")
        if f"Host: {expected_authority}" not in lines:
            raise AssertionError("Host header does not match CONNECT authority")
        reason = {200: "Connection Established", 407: "Proxy Authentication Required"}.get(
            status, "Bad Gateway"
        )
        conn.sendall(f"HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n".encode("ascii"))

    return handle


def encode_socks_target(host: str, port: int, remote_dns: bool) -> tuple[int, bytes]:
    if remote_dns:
        encoded = host.encode("idna")
        if not encoded or len(encoded) > 255:
            raise ValueError("SOCKS5 domain length is invalid")
        return 3, bytes([len(encoded)]) + encoded + struct.pack("!H", port)
    parsed = ipaddress.ip_address(host)
    atyp = 1 if parsed.version == 4 else 4
    return atyp, parsed.packed + struct.pack("!H", port)


def socks5_connect(
    port: int,
    host: str,
    target_port: int,
    *,
    remote_dns: bool = False,
    credentials: tuple[str, str] | None = None,
) -> int:
    methods = b"\x00\x02" if credentials else b"\x00"
    with connect_local(port) as conn:
        conn.sendall(b"\x05" + bytes([len(methods)]) + methods)
        version, method = recv_exact(conn, 2)
        if version != 5 or method == 0xFF:
            raise PermissionError("SOCKS5 authentication method rejected")
        if method == 2:
            if credentials is None:
                raise PermissionError("SOCKS5 proxy unexpectedly requires credentials")
            username, password = (item.encode("utf-8") for item in credentials)
            if not username or len(username) > 255 or len(password) > 255:
                raise ValueError("SOCKS5 credentials have invalid length")
            conn.sendall(b"\x01" + bytes([len(username)]) + username + bytes([len(password)]) + password)
            if recv_exact(conn, 2) != b"\x01\x00":
                raise PermissionError("SOCKS5 username/password authentication failed")
        atyp, encoded_target = encode_socks_target(host, target_port, remote_dns)
        conn.sendall(b"\x05\x01\x00" + bytes([atyp]) + encoded_target)
        version, reply, reserved, response_atyp = recv_exact(conn, 4)
        if version != 5 or reserved != 0:
            raise ValueError("malformed SOCKS5 response")
        address_size = {1: 4, 4: 16}.get(response_atyp)
        if response_atyp == 3:
            address_size = recv_exact(conn, 1)[0]
        if address_size is None:
            raise ValueError("invalid SOCKS5 response address type")
        recv_exact(conn, address_size + 2)
        return reply


def socks5_handler(
    expected_host: str,
    expected_port: int,
    *,
    remote_dns: bool = False,
    require_auth: bool = False,
    reply: int = 0,
) -> Callable[[socket.socket], None]:
    def handle(conn: socket.socket) -> None:
        version, method_count = recv_exact(conn, 2)
        methods = recv_exact(conn, method_count)
        selected = 2 if require_auth else 0
        if version != 5 or selected not in methods:
            conn.sendall(b"\x05\xff")
            return
        conn.sendall(b"\x05" + bytes([selected]))
        if require_auth:
            auth_version, username_size = recv_exact(conn, 2)
            username = recv_exact(conn, username_size)
            password_size = recv_exact(conn, 1)[0]
            password = recv_exact(conn, password_size)
            if auth_version != 1 or username != b"test-user" or password != b"test-password":
                conn.sendall(b"\x01\x01")
                return
            conn.sendall(b"\x01\x00")
        version, command, reserved, atyp = recv_exact(conn, 4)
        if (version, command, reserved) != (5, 1, 0):
            raise AssertionError("unexpected SOCKS5 CONNECT header")
        if atyp == 1:
            host = str(ipaddress.ip_address(recv_exact(conn, 4)))
        elif atyp == 4:
            host = str(ipaddress.ip_address(recv_exact(conn, 16)))
        elif atyp == 3:
            host = recv_exact(conn, recv_exact(conn, 1)[0]).decode("idna")
        else:
            raise AssertionError("unexpected SOCKS5 target address type")
        port = struct.unpack("!H", recv_exact(conn, 2))[0]
        if host != expected_host or port != expected_port or (atyp == 3) != remote_dns:
            raise AssertionError(f"unexpected SOCKS5 target: {host}:{port} atyp={atyp}")
        conn.sendall(b"\x05" + bytes([reply]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")

    return handle


def socks4_connect(
    port: int,
    host: str,
    target_port: int,
    *,
    remote_dns: bool = False,
    user_id: str = "",
) -> int:
    encoded_user = user_id.encode("utf-8")
    if len(encoded_user) > 255 or b"\x00" in encoded_user:
        raise ValueError("SOCKS4 USERID is invalid")
    if remote_dns:
        encoded_host = host.encode("idna")
        if not encoded_host or len(encoded_host) > 255 or b"\x00" in encoded_host:
            raise ValueError("SOCKS4a domain is invalid")
        address = b"\x00\x00\x00\x01"
        suffix = encoded_host + b"\x00"
    else:
        parsed = ipaddress.ip_address(host)
        if parsed.version != 4:
            raise ValueError("SOCKS4 requires an IPv4 target")
        address = parsed.packed
        suffix = b""
    request = b"\x04\x01" + struct.pack("!H", target_port) + address + encoded_user + b"\x00" + suffix
    with connect_local(port) as conn:
        conn.sendall(request)
        version, reply = recv_exact(conn, 2)
        recv_exact(conn, 6)
    if version != 0:
        raise ValueError("malformed SOCKS4 response")
    return reply


def socks4_handler(
    expected_host: str,
    expected_port: int,
    *,
    remote_dns: bool = False,
    expected_user_id: str = "",
    reply: int = 90,
) -> Callable[[socket.socket], None]:
    def handle(conn: socket.socket) -> None:
        version, command = recv_exact(conn, 2)
        port = struct.unpack("!H", recv_exact(conn, 2))[0]
        address = recv_exact(conn, 4)
        user_id = recv_cstring(conn).decode("utf-8")
        if (version, command) != (4, 1):
            raise AssertionError("unexpected SOCKS4 CONNECT header")
        if remote_dns:
            if address != b"\x00\x00\x00\x01":
                raise AssertionError("SOCKS4a request must use 0.0.0.1")
            host = recv_cstring(conn).decode("idna")
        else:
            host = str(ipaddress.ip_address(address))
        if host != expected_host or port != expected_port or user_id != expected_user_id:
            raise AssertionError(f"unexpected SOCKS4 target: {host}:{port} userid={user_id!r}")
        conn.sendall(b"\x00" + bytes([reply]) + struct.pack("!H", port) + address)

    return handle


def run_case(name: str, operation: Callable[[], None]) -> CaseResult:
    try:
        operation()
        return CaseResult(name, "pass", "contract matched")
    except Exception as exc:
        return CaseResult(name, "fail", f"{type(exc).__name__}: {exc}")


def assert_equal(actual: object, expected: object) -> None:
    if actual != expected:
        raise AssertionError(f"expected {expected!r}, got {actual!r}")


def resolve_proxy_config(
    *,
    cli_proxy: str | None = None,
    proxy_env_enabled: bool = False,
    proxy_family: str = "auto",
    env: dict[str, str] | None = None,
    restrictive_target_controls: bool = False,
) -> ProxyDecision | None:
    values = env or {}
    if proxy_family not in {"auto", "v4", "v6"}:
        raise ValueError("invalid proxy endpoint family")

    source = ""
    proxy_url = ""
    if cli_proxy:
        source, proxy_url = "cli", cli_proxy
    elif values.get("WHOIS_PROXY"):
        source, proxy_url = "WHOIS_PROXY", values["WHOIS_PROXY"]
    elif proxy_env_enabled and values.get("ALL_PROXY"):
        source, proxy_url = "ALL_PROXY", values["ALL_PROXY"]
    elif proxy_env_enabled and values.get("all_proxy"):
        source, proxy_url = "all_proxy", values["all_proxy"]
    else:
        return None

    try:
        parsed = urlsplit(proxy_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid proxy URL") from exc
    if parsed.scheme not in {"http", "socks4", "socks4a", "socks5", "socks5h"} or not parsed.hostname:
        raise ValueError("invalid proxy URL")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError("proxy URL has unsupported components")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("invalid proxy port")

    url_has_userinfo = parsed.username is not None or parsed.password is not None
    if source == "cli" and url_has_userinfo:
        raise ValueError("CLI proxy URL must not contain userinfo")
    if url_has_userinfo:
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if not username or not password:
            raise ValueError("proxy URL userinfo must be complete")

    dedicated_user = values.get("WHOIS_PROXY_USER")
    dedicated_password = values.get("WHOIS_PROXY_PASSWORD")
    dedicated_present = dedicated_user is not None or dedicated_password is not None
    if dedicated_present and (not dedicated_user or not dedicated_password):
        raise ValueError("dedicated proxy credentials must be complete")
    if dedicated_present and url_has_userinfo:
        raise ValueError("proxy credential sources are ambiguous")

    try:
        endpoint_ip = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        endpoint_ip = None
    if endpoint_ip is not None:
        expected_family = "v4" if endpoint_ip.version == 4 else "v6"
        if proxy_family != "auto" and proxy_family != expected_family:
            raise ValueError("proxy literal conflicts with endpoint family")
    if parsed.scheme in {"socks4a", "socks5h"} and restrictive_target_controls:
        raise ValueError("remote DNS conflicts with target family controls")

    return ProxyDecision(source, parsed.scheme, proxy_family, dedicated_present or url_has_userinfo)


def expect_config_error(operation: Callable[[], object]) -> None:
    try:
        operation()
    except ValueError:
        return
    raise AssertionError("expected proxy configuration rejection")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", default="out/artifacts/proxy_protocol_spike")
    args = parser.parse_args()

    cases: list[tuple[str, Callable[[], None]]] = []
    for name, host, target_port, status in (
        ("http-ipv4-custom-port", "192.0.2.10", 4043, 200),
        ("http-ipv6-authority", "2001:db8::10", 43, 200),
        ("http-auth-required", "192.0.2.20", 43, 407),
        ("http-bad-gateway", "192.0.2.30", 43, 502),
    ):
        authority = format_connect_authority(host, target_port)

        def http_operation(
            host: str = host,
            target_port: int = target_port,
            status: int = status,
            authority: str = authority,
        ) -> None:
            with OneShotProxy(http_handler(authority, status)) as proxy:
                assert_equal(http_connect(proxy.port, host, target_port), status)

        cases.append((name, http_operation))

    for name, host, target_port, remote_dns, require_auth, reply in (
        ("socks5-ipv4", "192.0.2.40", 43, False, False, 0),
        ("socks5-ipv6", "2001:db8::40", 4343, False, False, 0),
        ("socks5h-domain", "whois.example.test", 43, True, False, 0),
        ("socks5-userpass", "192.0.2.50", 43, False, True, 0),
        ("socks5-target-refused", "192.0.2.60", 43, False, False, 5),
    ):

        def socks_operation(
            host: str = host,
            target_port: int = target_port,
            remote_dns: bool = remote_dns,
            require_auth: bool = require_auth,
            reply: int = reply,
        ) -> None:
            with OneShotProxy(
                socks5_handler(
                    host,
                    target_port,
                    remote_dns=remote_dns,
                    require_auth=require_auth,
                    reply=reply,
                )
            ) as proxy:
                credentials = ("test-user", "test-password") if require_auth else None
                assert_equal(
                    socks5_connect(
                        proxy.port,
                        host,
                        target_port,
                        remote_dns=remote_dns,
                        credentials=credentials,
                    ),
                    reply,
                )

        cases.append((name, socks_operation))

    for name, host, target_port, remote_dns, user_id, reply in (
        ("socks4-ipv4", "192.0.2.70", 43, False, "", 90),
        ("socks4-userid", "192.0.2.71", 4343, False, "test-user", 90),
        ("socks4a-domain", "whois.example.test", 43, True, "test-user", 90),
        ("socks4-target-rejected", "192.0.2.72", 43, False, "", 91),
    ):

        def socks4_operation(
            host: str = host,
            target_port: int = target_port,
            remote_dns: bool = remote_dns,
            user_id: str = user_id,
            reply: int = reply,
        ) -> None:
            with OneShotProxy(
                socks4_handler(
                    host,
                    target_port,
                    remote_dns=remote_dns,
                    expected_user_id=user_id,
                    reply=reply,
                )
            ) as proxy:
                assert_equal(
                    socks4_connect(
                        proxy.port,
                        host,
                        target_port,
                        remote_dns=remote_dns,
                        user_id=user_id,
                    ),
                    reply,
                )

        cases.append((name, socks4_operation))

    cases.extend(
        (
            (
                "config-default-direct",
                lambda: assert_equal(resolve_proxy_config(), None),
            ),
            (
                "config-cli-precedence",
                lambda: assert_equal(
                    resolve_proxy_config(
                        cli_proxy="http://proxy.example.test:8080",
                        proxy_env_enabled=True,
                        env={"WHOIS_PROXY": "socks5://ignored.example.test:1080"},
                    ),
                    ProxyDecision("cli", "http", "auto", False),
                ),
            ),
            (
                "config-generic-env-opt-in",
                lambda: assert_equal(
                    resolve_proxy_config(
                        proxy_env_enabled=True,
                        env={"ALL_PROXY": "socks5://proxy.example.test:1080"},
                    ),
                    ProxyDecision("ALL_PROXY", "socks5", "auto", False),
                ),
            ),
            (
                "config-generic-env-ignored",
                lambda: assert_equal(
                    resolve_proxy_config(env={"ALL_PROXY": "socks5://proxy.example.test:1080"}),
                    None,
                ),
            ),
            (
                "config-dedicated-credentials",
                lambda: assert_equal(
                    resolve_proxy_config(
                        cli_proxy="socks5://proxy.example.test:1080",
                        env={
                            "WHOIS_PROXY_USER": "test-user",
                            "WHOIS_PROXY_PASSWORD": "test-password",
                        },
                    ),
                    ProxyDecision("cli", "socks5", "auto", True),
                ),
            ),
            (
                "config-env-url-userinfo",
                lambda: assert_equal(
                    resolve_proxy_config(
                        env={"WHOIS_PROXY": "http://test-user:test-password@proxy.example.test:8080"}
                    ),
                    ProxyDecision("WHOIS_PROXY", "http", "auto", True),
                ),
            ),
            (
                "config-cli-userinfo-rejected",
                lambda: expect_config_error(
                    lambda: resolve_proxy_config(
                        cli_proxy="http://test-user:test-password@proxy.example.test:8080"
                    )
                ),
            ),
            (
                "config-partial-credentials-rejected",
                lambda: expect_config_error(
                    lambda: resolve_proxy_config(
                        cli_proxy="socks5://proxy.example.test:1080",
                        env={"WHOIS_PROXY_USER": "test-user"},
                    )
                ),
            ),
            (
                "config-ambiguous-credentials-rejected",
                lambda: expect_config_error(
                    lambda: resolve_proxy_config(
                        env={
                            "WHOIS_PROXY": "socks5://url-user:url-password@proxy.example.test:1080",
                            "WHOIS_PROXY_USER": "dedicated-user",
                            "WHOIS_PROXY_PASSWORD": "dedicated-password",
                        }
                    )
                ),
            ),
            (
                "config-proxy-family-v6",
                lambda: assert_equal(
                    resolve_proxy_config(
                        cli_proxy="http://[2001:db8::80]:8080", proxy_family="v6"
                    ),
                    ProxyDecision("cli", "http", "v6", False),
                ),
            ),
            (
                "config-proxy-family-conflict",
                lambda: expect_config_error(
                    lambda: resolve_proxy_config(
                        cli_proxy="http://192.0.2.80:8080", proxy_family="v6"
                    )
                ),
            ),
            (
                "config-socks5h-target-controls-rejected",
                lambda: expect_config_error(
                    lambda: resolve_proxy_config(
                        cli_proxy="socks5h://proxy.example.test:1080",
                        restrictive_target_controls=True,
                    )
                ),
            ),
            (
                "config-socks4-supported",
                lambda: assert_equal(
                    resolve_proxy_config(cli_proxy="socks4://proxy.example.test:1080"),
                    ProxyDecision("cli", "socks4", "auto", False),
                ),
            ),
            (
                "config-socks4a-target-controls-rejected",
                lambda: expect_config_error(
                    lambda: resolve_proxy_config(
                        cli_proxy="socks4a://proxy.example.test:1080",
                        restrictive_target_controls=True,
                    )
                ),
            ),
        )
    )

    results = [run_case(name, operation) for name, operation in cases]
    now = datetime.now(timezone.utc)
    output_dir = Path(args.output_root) / now.strftime("%Y%m%d-%H%M%S")
    output_dir.mkdir(parents=True, exist_ok=False)
    report = {
        "schemaVersion": 1,
        "result": "pass" if all(item.status == "pass" for item in results) else "fail",
        "generatedAt": now.isoformat(),
        "network": "IPv4 loopback only",
        "cases": [asdict(item) for item in results],
        "summary": {
            "total": len(results),
            "passed": sum(item.status == "pass" for item in results),
            "failed": sum(item.status == "fail" for item in results),
        },
    }
    report_path = output_dir / "report.json"
    report_text = json.dumps(report, indent=2) + "\n"
    for secret in ("test-password", "url-password", "dedicated-password"):
        if secret in report_text:
            raise RuntimeError("proxy protocol report contains credential material")
    report_path.write_text(report_text, encoding="utf-8")
    print(
        f"[PROXY-PROTOCOL-SPIKE] result={report['result']} "
        f"passed={report['summary']['passed']} failed={report['summary']['failed']} "
        f"report={report_path}"
    )
    for item in results:
        print(f"[PROXY-PROTOCOL-SPIKE] case={item.name} status={item.status} detail={item.detail}")
    return 0 if report["result"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())