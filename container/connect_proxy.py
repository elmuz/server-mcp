#!/usr/bin/env python3
"""Open a TCP stream through the Server MCP egress proxy.

This is an SSH ``ProxyCommand`` helper. It speaks HTTP CONNECT to the
policy-enforcing proxy, then relays stdin/stdout to the tunnel. The proxy, not
this helper, decides whether the destination is allowed.

Usage:
    server-mcp-connect PROXY_HOST PROXY_PORT TARGET_HOST TARGET_PORT
"""

from __future__ import annotations

import select
import socket
import sys


def _authority(host: str, port: int) -> str:
    if ":" in host and not host.startswith("["):
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _read_headers(sock: socket.socket) -> tuple[bytes, bytes]:
    data = b""
    while b"\r\n\r\n" not in data and b"\n\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("proxy closed the connection before responding")
        data += chunk
        if len(data) > 65536:
            raise RuntimeError("proxy response headers are too large")
    if b"\r\n\r\n" in data:
        headers, extra = data.split(b"\r\n\r\n", 1)
    else:
        headers, extra = data.split(b"\n\n", 1)
    return headers, extra


def main(argv: list[str]) -> int:
    if len(argv) != 5:
        print(
            "usage: server-mcp-connect PROXY_HOST PROXY_PORT TARGET_HOST TARGET_PORT",
            file=sys.stderr,
        )
        return 2

    proxy_host, proxy_port_text, target_host, target_port_text = argv[1:]
    try:
        proxy_port = int(proxy_port_text)
        target_port = int(target_port_text)
    except ValueError:
        print("proxy and target ports must be integers", file=sys.stderr)
        return 2

    authority = _authority(target_host, target_port)
    try:
        upstream = socket.create_connection((proxy_host, proxy_port), timeout=15)
    except OSError as exc:
        print(
            f"cannot connect to egress proxy {proxy_host}:{proxy_port}: {exc}",
            file=sys.stderr,
        )
        return 1

    try:
        request = (
            f"CONNECT {authority} HTTP/1.1\r\n"
            f"Host: {authority}\r\n"
            "Proxy-Connection: keep-alive\r\n"
            "\r\n"
        ).encode("ascii")
        upstream.sendall(request)
        response, extra = _read_headers(upstream)
        status_line = response.splitlines()[0] if response.splitlines() else b""
        if b" 200 " not in status_line and not status_line.endswith(b" 200"):
            detail = status_line.decode("latin-1", "replace")
            print(f"egress proxy refused {authority}: {detail}", file=sys.stderr)
            return 1

        stdin = sys.stdin.buffer
        stdout = sys.stdout.buffer
        if extra:
            stdout.write(extra)
            stdout.flush()

        stdin_open = True
        while True:
            # SSH connections can be idle between tool calls; a short idle
            # timeout would drop a healthy session.
            watched = [stdin, upstream] if stdin_open else [upstream]
            readable, _, _ = select.select(watched, [], [], 3600)
            if not readable:
                return 0
            for source in readable:
                if source is stdin:
                    data = stdin.read1(65536)
                    if not data:
                        # Half-close the tunnel but keep reading the response.
                        stdin_open = False
                        try:
                            upstream.shutdown(socket.SHUT_WR)
                        except OSError:
                            return 0
                        continue
                    upstream.sendall(data)
                else:
                    data = upstream.recv(65536)
                    if not data:
                        return 0
                    stdout.write(data)
                    stdout.flush()
    except (OSError, RuntimeError) as exc:
        print(f"egress proxy tunnel failed: {exc}", file=sys.stderr)
        return 1
    finally:
        upstream.close()


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
