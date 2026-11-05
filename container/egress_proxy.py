#!/usr/bin/env python3
"""Policy-enforcing HTTP/HTTPS proxy for the Pi sandbox.

The proxy is the only container with a route to the public internet. Sandbox
containers join an internal Podman network and send HTTP(S) traffic here. The
policy denies destinations by default, always blocks non-global addresses, and
supports explicit allow/deny entries for hostnames, IPs and CIDRs. Explicit
deny entries win over explicit allow entries. ``default allow`` restores the
legacy public-by-default behaviour for a personal policy.

Policy file syntax (one rule per line, ``#`` starts a comment):

    default deny
    allow api.openai.com 443
    deny  mcp.example.com
    deny  203.0.113.10
    deny  203.0.113.0/24
    allow 192.168.1.50
    allow 192.168.1.0/24 80
    allow docs.internal:443

A trailing port is optional. For IPv6, use ``[2001:db8::1]:443`` or put the
port in a separate field. Hostname entries also match subdomains.
"""

from __future__ import annotations

import argparse
import ipaddress
import logging
import select
import socket
import socketserver
import sys
import time
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

LOGGER = logging.getLogger("pi-egress-proxy")

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network


class PolicyError(ValueError):
    """The policy file is malformed."""


class ClientDisconnectedError(Exception):
    """The client closed the connection before sending a request.

    Container healthchecks probe the proxy by opening a TCP connection and
    closing it immediately. That is a successful liveness check, not a bad
    request, so it must not be logged as a warning.
    """


@dataclass(frozen=True)
class ResolvedAddress:
    """One validated destination address."""

    family: int
    sockaddr: tuple
    ip: IPAddress


@dataclass(frozen=True)
class Rule:
    """One allow or deny entry from the policy file."""

    action: str
    target: str
    port: int | None
    network: IPNetwork | None = None
    name: str | None = None

    def matches_port(self, port: int) -> bool:
        return self.port is None or self.port == port


@dataclass(frozen=True)
class Decision:
    """The policy result for one destination."""

    allowed: bool
    reason: str
    host: str
    port: int
    addresses: tuple[ResolvedAddress, ...] = ()

    @property
    def first_address(self) -> ResolvedAddress | None:
        return self.addresses[0] if self.addresses else None


def _address_from_ip(ip: IPAddress, port: int) -> ResolvedAddress:
    if ip.version == 4:
        return ResolvedAddress(socket.AF_INET, (str(ip), port), ip)
    return ResolvedAddress(socket.AF_INET6, (str(ip), port, 0, 0), ip)


def resolve_addresses(host: str, port: int) -> tuple[ResolvedAddress, ...]:
    """Resolve a hostname to validated-looking socket addresses."""

    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    result: list[ResolvedAddress] = []
    seen: set[tuple[int, str]] = set()
    for family, _socktype, _proto, _canonname, sockaddr in infos:
        ip = ipaddress.ip_address(sockaddr[0])
        key = (family, str(ip))
        if key in seen:
            continue
        seen.add(key)
        result.append(ResolvedAddress(family, sockaddr, ip))
    return tuple(result)


def normalize_host(host: str) -> str:
    host = host.strip().lower()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host.rstrip(".")


def _split_inline_port(token: str) -> tuple[str, int | None]:
    if token.startswith("["):
        end = token.find("]")
        if end == -1:
            raise PolicyError(f"unterminated IPv6 literal: {token}")
        host = token[1:end]
        suffix = token[end + 1 :]
        if not suffix:
            return host, None
        if not suffix.startswith(":"):
            raise PolicyError(f"invalid IPv6 target: {token}")
        return host, _parse_port(suffix[1:])
    if token.count(":") == 1:
        host, port = token.rsplit(":", 1)
        if port == "*" or port.isdigit():
            return host, _parse_port(port)
    return token, None


def _parse_port(value: str) -> int | None:
    if value == "*":
        return None
    if not value.isdigit():
        raise PolicyError(f"invalid port: {value}")
    port = int(value)
    if not 1 <= port <= 65535:
        raise PolicyError(f"port out of range: {value}")
    return port


def _parse_target(token: str) -> tuple[IPNetwork | None, str | None]:
    token = token.strip()
    if not token:
        raise PolicyError("empty target")
    if "/" in token:
        try:
            network = ipaddress.ip_network(token, strict=False)
        except ValueError as exc:
            raise PolicyError(f"invalid network: {token}") from exc
        return network, None
    try:
        ip = ipaddress.ip_address(token)
    except ValueError:
        name = normalize_host(token)
        if not name or any(char.isspace() for char in name) or "/" in name:
            raise PolicyError(f"invalid hostname: {token}")
        if name.startswith("*."):
            name = name[2:]
        if name.startswith("."):
            name = name[1:]
        if not name:
            raise PolicyError(f"invalid hostname: {token}")
        return None, name
    suffix = "/32" if ip.version == 4 else "/128"
    return ipaddress.ip_network(f"{ip}{suffix}", strict=False), None


def parse_rule(line: str, lineno: int) -> Rule | None:
    text = line.split("#", 1)[0].strip()
    if not text:
        return None
    parts = text.split()
    action = parts[0].lower()
    if action == "default":
        if len(parts) != 2 or parts[1].lower() not in ("allow", "deny"):
            raise PolicyError(
                f"line {lineno}: expected 'default allow' or 'default deny'"
            )
        return Rule(action="default", target=parts[1].lower(), port=None)
    if len(parts) not in (2, 3):
        raise PolicyError(f"line {lineno}: expected 'allow|deny TARGET [PORT]'")
    if action not in ("allow", "deny"):
        raise PolicyError(f"line {lineno}: unknown action {parts[0]!r}")
    target, inline_port = _split_inline_port(parts[1])
    if len(parts) == 3:
        if inline_port is not None:
            raise PolicyError(f"line {lineno}: port specified twice")
        port = _parse_port(parts[2])
    else:
        port = inline_port
    network, name = _parse_target(target)
    return Rule(action=action, target=target, port=port, network=network, name=name)


def load_rules(path: str | Path) -> list[Rule]:
    rules: list[Rule] = []
    try:
        lines = Path(path).read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise PolicyError(f"cannot read policy {path}: {exc}") from exc
    for lineno, line in enumerate(lines, start=1):
        rule = parse_rule(line, lineno)
        if rule is not None:
            rules.append(rule)
    return rules


def _name_matches(host: str, rule_name: str) -> bool:
    return host == rule_name or host.endswith("." + rule_name)


class Policy:
    """Destination policy with a short-lived cache for name-based rules."""

    def __init__(
        self,
        rules: Iterable[Rule],
        resolver: Callable[[str, int], Sequence[ResolvedAddress]] = resolve_addresses,
        name_cache_ttl: float = 60.0,
    ) -> None:
        rules = tuple(rules)
        defaults = [rule for rule in rules if rule.action == "default"]
        self.rules = tuple(rule for rule in rules if rule.action != "default")
        self.default_allow = bool(defaults and defaults[-1].target == "allow")
        self._resolver = resolver
        self._name_cache_ttl = name_cache_ttl
        self._name_cache: dict[str, tuple[float, tuple[IPAddress, ...]]] = {}

    @classmethod
    def from_file(cls, path: str | Path, **kwargs: object) -> Policy:
        return cls(load_rules(path), **kwargs)  # type: ignore[arg-type]

    def _resolve_name_ips(self, name: str) -> tuple[IPAddress, ...]:
        now = time.monotonic()
        cached = self._name_cache.get(name)
        if cached is not None and now - cached[0] < self._name_cache_ttl:
            return cached[1]
        try:
            addresses = self._resolver(name, 0)
        except OSError:
            LOGGER.warning("cannot resolve policy hostname %s", name)
            addresses = ()
        ips = tuple(dict.fromkeys(address.ip for address in addresses))
        self._name_cache[name] = (now, ips)
        return ips

    @staticmethod
    def _baseline_denied(ip: IPAddress) -> bool:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        return not ip.is_global

    def _rule_matches_ip(self, rule: Rule, ip: IPAddress, port: int) -> bool:
        if rule.name is not None:
            return rule.matches_port(port) and ip in self._resolve_name_ips(rule.name)
        return (
            rule.network is not None and rule.matches_port(port) and ip in rule.network
        )

    def check(self, host: str, port: int) -> Decision:
        host = normalize_host(host)
        if not host:
            return Decision(False, "empty destination", host, port)
        if not 1 <= port <= 65535:
            return Decision(False, "invalid destination port", host, port)

        deny_rules = [rule for rule in self.rules if rule.action == "deny"]
        allow_rules = [rule for rule in self.rules if rule.action == "allow"]

        for rule in deny_rules:
            if (
                rule.name is not None
                and rule.matches_port(port)
                and _name_matches(host, rule.name)
            ):
                return Decision(False, f"explicit deny {rule.target}", host, port)

        name_allowed = any(
            rule.name is not None
            and rule.matches_port(port)
            and _name_matches(host, rule.name)
            for rule in allow_rules
        )

        try:
            literal_ip = ipaddress.ip_address(host)
        except ValueError:
            literal_ip = None

        if literal_ip is not None:
            addresses = (_address_from_ip(literal_ip, port),)
        else:
            try:
                addresses = self._resolver(host, port)
            except OSError:
                return Decision(False, "DNS resolution failed", host, port)
            if not addresses:
                return Decision(
                    False, "DNS resolution returned no addresses", host, port
                )

        explicit_allowed = name_allowed
        for address in addresses:
            ip = address.ip
            for rule in deny_rules:
                if self._rule_matches_ip(rule, ip, port):
                    return Decision(False, f"explicit deny {rule.target}", host, port)

            allowed_by_ip = any(
                self._rule_matches_ip(rule, ip, port) for rule in allow_rules
            )
            if name_allowed or allowed_by_ip:
                explicit_allowed = True
                continue

            if self._baseline_denied(ip):
                return Decision(
                    False, f"non-public address {ip}", host, port, tuple(addresses)
                )

            if not self.default_allow:
                return Decision(
                    False, "not explicitly allowed", host, port, tuple(addresses)
                )

        return Decision(
            True,
            "explicit allow" if explicit_allowed else "default allow",
            host,
            port,
            tuple(addresses),
        )

    def summary(self) -> str:
        deny = sum(1 for rule in self.rules if rule.action == "deny")
        allow = sum(1 for rule in self.rules if rule.action == "allow")
        default = "allow" if self.default_allow else "deny"
        return (
            f"{len(self.rules)} rules ({deny} deny, {allow} allow), default {default}"
        )


def _split_host_port(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        end = target.find("]")
        if end == -1:
            raise ValueError("unterminated IPv6 literal")
        host = target[1:end]
        suffix = target[end + 1 :]
        if not suffix:
            return host, default_port
        if not suffix.startswith(":"):
            raise ValueError("invalid authority")
        return host, _parse_port(suffix[1:]) or default_port
    if target.count(":") == 1:
        host, port = target.rsplit(":", 1)
        return host, _parse_port(port) or default_port
    if target.count(":") > 1:
        return target, default_port
    return target, default_port


def _connect(addresses: Sequence[ResolvedAddress]) -> socket.socket | None:
    for address in addresses:
        sock = socket.socket(address.family, socket.SOCK_STREAM)
        sock.settimeout(15)
        try:
            sock.connect(address.sockaddr)
        except OSError:
            sock.close()
            continue
        return sock
    return None


def _relay(client: socket.socket, upstream: socket.socket) -> None:
    peers = {client: upstream, upstream: client}
    open_socks = {client, upstream}
    try:
        while open_socks:
            # SSH tunnels can be idle between tool calls; a short idle
            # timeout would drop a healthy session.
            readable, _, _ = select.select(list(open_socks), [], [], 3600)
            if not readable:
                return
            for source in readable:
                data = source.recv(65536)
                if not data:
                    # Propagate a half-close instead of tearing down the
                    # other direction. SSH and HTTP both rely on this.
                    open_socks.discard(source)
                    try:
                        peers[source].shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    continue
                peers[source].sendall(data)
    except OSError:
        return
    finally:
        for sock in (client, upstream):
            try:
                sock.close()
            except OSError:
                pass


class ProxyHandler(socketserver.BaseRequestHandler):
    """One HTTP proxy request; CONNECT becomes a raw TCP tunnel."""

    def setup(self) -> None:
        self.request.settimeout(30)

    def handle(self) -> None:
        try:
            request_line, headers, initial_body = self._read_request()
            self._dispatch(request_line, headers, initial_body)
        except ClientDisconnectedError:
            LOGGER.debug(
                "client %s connected and closed without a request",
                self.client_address[0],
            )
        except (OSError, ValueError, UnicodeError) as exc:
            LOGGER.warning("bad request from %s: %s", self.client_address[0], exc)
            self._send_error(400, "Bad Request")

    def _read_request(self) -> tuple[str, list[tuple[str, str]], bytes]:
        buffer = b""
        while b"\r\n\r\n" not in buffer and b"\n\n" not in buffer:
            chunk = self.request.recv(65536)
            if not chunk:
                if not buffer:
                    raise ClientDisconnectedError
                raise ValueError("incomplete request")
            buffer += chunk
            if len(buffer) > 131072:
                raise ValueError("request headers too large")
        if b"\r\n\r\n" in buffer:
            head, body = buffer.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
        else:
            head, body = buffer.split(b"\n\n", 1)
            lines = head.decode("latin-1").split("\n")
        if not lines or not lines[0]:
            raise ValueError("missing request line")
        headers: list[tuple[str, str]] = []
        for line in lines[1:]:
            if not line:
                continue
            if ":" not in line:
                raise ValueError("malformed header")
            name, value = line.split(":", 1)
            headers.append((name.strip(), value.strip()))
        return lines[0], headers, body

    def _dispatch(
        self, request_line: str, headers: list[tuple[str, str]], initial_body: bytes
    ) -> None:
        parts = request_line.split()
        if len(parts) != 3:
            self._send_error(400, "Bad Request")
            return
        method, target, version = parts
        policy: Policy = self.server.policy  # type: ignore[attr-defined]

        if method.upper() == "CONNECT":
            try:
                host, port = _split_host_port(target, 443)
            except ValueError:
                self._send_error(400, "Bad Request")
                return
            decision = policy.check(host, port)
            self._log_decision(decision)
            if not decision.allowed:
                self._send_error(403, "Forbidden")
                return
            upstream = _connect(decision.addresses)
            if upstream is None:
                self._send_error(502, "Bad Gateway")
                return
            try:
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except OSError:
                upstream.close()
                return
            _relay(self.request, upstream)
            return

        parsed = urlsplit(target)
        if parsed.scheme.lower() != "http" or not parsed.hostname:
            self._send_error(400, "Bad Request: absolute http URL required")
            return
        try:
            port = parsed.port or 80
        except ValueError:
            self._send_error(400, "Bad Request")
            return
        decision = policy.check(parsed.hostname, port)
        self._log_decision(decision)
        if not decision.allowed:
            self._send_error(403, "Forbidden")
            return
        upstream = _connect(decision.addresses)
        if upstream is None:
            self._send_error(502, "Bad Gateway")
            return

        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        forwarded: list[tuple[str, str]] = []
        for name, value in headers:
            if name.lower() in {
                "proxy-connection",
                "proxy-authorization",
                "connection",
                "keep-alive",
            }:
                continue
            forwarded.append((name, value))
        forwarded.append(("Connection", "close"))
        head = f"{method} {path} {version}\r\n"
        head += "".join(f"{name}: {value}\r\n" for name, value in forwarded)
        head += "\r\n"
        try:
            upstream.sendall(head.encode("latin-1"))
            if initial_body:
                upstream.sendall(initial_body)
        except OSError:
            upstream.close()
            self._send_error(502, "Bad Gateway")
            return
        _relay(self.request, upstream)

    def _log_decision(self, decision: Decision) -> None:
        verdict = "ALLOW" if decision.allowed else "DENY"
        address = str(decision.first_address.ip) if decision.first_address else "-"
        LOGGER.info(
            "%s host=%s port=%s ip=%s reason=%s",
            verdict,
            decision.host,
            decision.port,
            address,
            decision.reason,
        )

    def _send_error(self, code: int, message: str) -> None:
        body = f"{code} {message}\n".encode()
        response = (
            f"HTTP/1.1 {code} {message}\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("latin-1") + body
        try:
            self.request.sendall(response)
        except OSError:
            pass


class ProxyServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        policy: Policy,
    ) -> None:
        self.policy = policy
        super().__init__(server_address, ProxyHandler)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Policy-enforcing Pi egress proxy")
    parser.add_argument(
        "--listen",
        default="0.0.0.0",
        help="listen address (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=3128,
        help="listen port (default: 3128)",
    )
    parser.add_argument(
        "--policy",
        default="/etc/pi-egress/policy.conf",
        help="policy file (default: /etc/pi-egress/policy.conf)",
    )
    parser.add_argument(
        "--check-policy",
        action="store_true",
        help="validate the policy and exit",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=("DEBUG", "INFO", "WARNING", "ERROR"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    try:
        policy = Policy.from_file(args.policy)
    except PolicyError as exc:
        print(f"invalid egress policy: {exc}", file=sys.stderr)
        return 2
    if args.check_policy:
        print(f"valid egress policy: {args.policy} ({policy.summary()})")
        return 0
    server = ProxyServer((args.listen, args.port), policy)
    LOGGER.info(
        "listening on %s:%s with %s from %s",
        args.listen,
        args.port,
        policy.summary(),
        args.policy,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
