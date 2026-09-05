#!/usr/bin/env python3
"""Bounded CONNECT proxy for CTF model API egress."""

from __future__ import annotations

import ipaddress
import os
import re
import selectors
import socket
import socketserver
import struct
import sys
import threading
import unittest

HEADER_LIMIT = 16 * 1024
CLIENT_HELLO_LIMIT = 64 * 1024
CONNECT_TIMEOUT_SECONDS = 10
IDLE_TIMEOUT_SECONDS = 300
HOST_PATTERN = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$")


def normalized_host(value: str) -> str:
    host = value.rstrip(".").lower()
    if not HOST_PATTERN.fullmatch(host) or ".." in host:
        raise ValueError("invalid host")
    return host


def allowed_hosts_from_environment() -> frozenset[str]:
    raw = os.environ.get("GUARD_EGRESS_ALLOW_HOSTS", "")
    hosts = frozenset(normalized_host(item.strip()) for item in raw.split(",") if item.strip())
    if not hosts:
        raise ValueError("GUARD_EGRESS_ALLOW_HOSTS must name at least one exact host")
    return hosts


def parse_connect_request(data: bytes, allowed_hosts: frozenset[str]) -> str:
    try:
        request_line = data.split(b"\r\n", 1)[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("request line is not ASCII") from error
    parts = request_line.split(" ")
    if len(parts) != 3 or parts[0] != "CONNECT" or parts[2] != "HTTP/1.1":
        raise ValueError("only HTTP/1.1 CONNECT is supported")
    authority = parts[1]
    if authority.count(":") != 1:
        raise ValueError("CONNECT authority must be an exact DNS host and port")
    host_value, port_value = authority.rsplit(":", 1)
    host = normalized_host(host_value)
    if port_value != "443" or host not in allowed_hosts:
        raise ValueError("CONNECT target is not allowed")
    return host


def tls_client_hello_server_name(data: bytes) -> str | None:
    """Return the first ClientHello SNI once complete, otherwise None."""
    offset = 0
    handshake = bytearray()
    while offset + 5 <= len(data):
        content_type, major, _minor, length = struct.unpack("!BBBH", data[offset : offset + 5])
        record_end = offset + 5 + length
        if record_end > len(data):
            return None
        if content_type != 22 or major != 3:
            raise ValueError("tunnel must begin with a TLS handshake")
        handshake.extend(data[offset + 5 : record_end])
        offset = record_end
        if len(handshake) < 4:
            continue
        if handshake[0] != 1:
            raise ValueError("first TLS handshake message must be ClientHello")
        message_length = int.from_bytes(handshake[1:4], "big")
        if message_length + 4 > CLIENT_HELLO_LIMIT:
            raise ValueError("TLS ClientHello is too large")
        if len(handshake) < message_length + 4:
            continue
        return parse_client_hello_server_name(bytes(handshake[4 : message_length + 4]))
    return None


def parse_client_hello_server_name(hello: bytes) -> str:
    cursor = 0

    def take(length: int) -> bytes:
        nonlocal cursor
        end = cursor + length
        if end > len(hello):
            raise ValueError("truncated TLS ClientHello")
        value = hello[cursor:end]
        cursor = end
        return value

    take(2 + 32)
    take(int.from_bytes(take(1), "big"))
    take(int.from_bytes(take(2), "big"))
    take(int.from_bytes(take(1), "big"))
    extensions_length = int.from_bytes(take(2), "big")
    extensions_end = cursor + extensions_length
    if extensions_end != len(hello):
        raise ValueError("invalid TLS extension block")
    while cursor < extensions_end:
        extension_type = int.from_bytes(take(2), "big")
        extension_data = take(int.from_bytes(take(2), "big"))
        if extension_type != 0:
            continue
        if len(extension_data) < 5:
            raise ValueError("invalid TLS SNI extension")
        names_length = int.from_bytes(extension_data[:2], "big")
        if names_length != len(extension_data) - 2:
            raise ValueError("invalid TLS SNI list")
        name_type = extension_data[2]
        name_length = int.from_bytes(extension_data[3:5], "big")
        if name_type != 0 or name_length != len(extension_data) - 5:
            raise ValueError("TLS ClientHello must carry one DNS SNI name")
        try:
            return normalized_host(extension_data[5:].decode("ascii"))
        except UnicodeDecodeError as error:
            raise ValueError("TLS SNI is not ASCII") from error
    raise ValueError("TLS ClientHello has no SNI")


def resolve_public(host: str) -> list[tuple[int, int, int, str, tuple[object, ...]]]:
    addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    public = []
    for address in addresses:
        ip = ipaddress.ip_address(address[4][0])
        if ip.is_global:
            public.append(address)
    if not public:
        raise ValueError("allowed host has no public address")
    return public


def connect_public(host: str) -> socket.socket:
    last_error: OSError | None = None
    for family, socktype, protocol, _canonical_name, sockaddr in resolve_public(host):
        upstream = socket.socket(family, socktype, protocol)
        upstream.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            upstream.connect(sockaddr)
            upstream.settimeout(None)
            return upstream
        except OSError as error:
            last_error = error
            upstream.close()
    raise last_error or OSError("no public address accepted the connection")


def receive_until(client: socket.socket, marker: bytes, limit: int) -> bytes:
    data = bytearray()
    while marker not in data:
        chunk = client.recv(min(4096, limit - len(data)))
        if not chunk:
            raise ValueError("connection closed before request completed")
        data.extend(chunk)
        if len(data) >= limit and marker not in data:
            raise ValueError("request exceeds size limit")
    return bytes(data)


def receive_client_hello(client: socket.socket, initial: bytes = b"") -> tuple[bytes, str]:
    data = bytearray(initial)
    while len(data) < CLIENT_HELLO_LIMIT:
        server_name = tls_client_hello_server_name(bytes(data))
        if server_name is not None:
            return bytes(data), server_name
        chunk = client.recv(min(4096, CLIENT_HELLO_LIMIT - len(data)))
        if not chunk:
            raise ValueError("connection closed before TLS ClientHello")
        data.extend(chunk)
    raise ValueError("TLS ClientHello exceeds size limit")


def relay(client: socket.socket, upstream: socket.socket) -> None:
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, upstream)
    selector.register(upstream, selectors.EVENT_READ, client)
    try:
        while True:
            events = selector.select(IDLE_TIMEOUT_SECONDS)
            if not events:
                return
            for key, _events in events:
                source = key.fileobj
                destination = key.data
                chunk = source.recv(64 * 1024)
                if not chunk:
                    return
                destination.sendall(chunk)
    finally:
        selector.close()


class ConnectHandler(socketserver.BaseRequestHandler):
    allowed_hosts: frozenset[str]
    connector = staticmethod(connect_public)

    def handle(self) -> None:
        client = self.request
        client.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            request = receive_until(client, b"\r\n\r\n", HEADER_LIMIT)
            header, buffered_tunnel = request.split(b"\r\n\r\n", 1)
            host = parse_connect_request(header + b"\r\n\r\n", self.allowed_hosts)
            upstream = self.connector(host)
            try:
                client.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                buffered, server_name = receive_client_hello(client, buffered_tunnel)
                if server_name != host:
                    raise ValueError("TLS SNI does not match CONNECT host")
                upstream.sendall(buffered)
                client.settimeout(None)
                relay(client, upstream)
            finally:
                upstream.close()
        except (OSError, ValueError):
            try:
                client.sendall(b"HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            except OSError:
                pass


class ThreadingServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = False
    daemon_threads = True


def serve() -> None:
    ConnectHandler.allowed_hosts = allowed_hosts_from_environment()
    with ThreadingServer(("0.0.0.0", 3128), ConnectHandler) as server:
        server.serve_forever()


class ProxyTests(unittest.TestCase):
    @staticmethod
    def client_hello(host: str) -> bytes:
        encoded_host = host.encode("ascii")
        server_name = b"\x00" + len(encoded_host).to_bytes(2, "big") + encoded_host
        sni = len(server_name).to_bytes(2, "big") + server_name
        extension = b"\x00\x00" + len(sni).to_bytes(2, "big") + sni
        hello = (
            b"\x03\x03"
            + (b"\x00" * 32)
            + b"\x00"
            + b"\x00\x02\x13\x01"
            + b"\x01\x00"
            + len(extension).to_bytes(2, "big")
            + extension
        )
        handshake = b"\x01" + len(hello).to_bytes(3, "big") + hello
        return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake

    def test_connect_allowlist_is_exact(self) -> None:
        allowed = frozenset({"openrouter.ai"})
        self.assertEqual(
            parse_connect_request(b"CONNECT openrouter.ai:443 HTTP/1.1\r\n\r\n", allowed),
            "openrouter.ai",
        )
        for authority in ("example.com:443", "openrouter.ai:80", "127.0.0.1:443"):
            with self.subTest(authority=authority), self.assertRaises(ValueError):
                parse_connect_request(f"CONNECT {authority} HTTP/1.1\r\n\r\n".encode(), allowed)

    def test_non_connect_request_is_denied(self) -> None:
        with self.assertRaises(ValueError):
            parse_connect_request(
                b"GET http://openrouter.ai/ HTTP/1.1\r\n\r\n",
                frozenset({"openrouter.ai"}),
            )

    def test_private_resolution_is_denied(self) -> None:
        original = socket.getaddrinfo
        socket.getaddrinfo = lambda *_args, **_kwargs: [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 443))
        ]
        try:
            with self.assertRaises(ValueError):
                resolve_public("openrouter.ai")
        finally:
            socket.getaddrinfo = original

    def test_tls_sni_is_extracted_across_records(self) -> None:
        record = self.client_hello("openrouter.ai")
        self.assertEqual(tls_client_hello_server_name(record), "openrouter.ai")
        self.assertIsNone(tls_client_hello_server_name(record[:-1]))

    def test_tls_without_sni_is_denied(self) -> None:
        record = self.client_hello("openrouter.ai")
        with self.assertRaises(ValueError):
            tls_client_hello_server_name(record[:-4] + b"\x00\x01\x00\x00")

    def test_upstream_failure_returns_403_before_connect_success(self) -> None:
        original = ConnectHandler.connector

        def fail_connect(_host: str) -> socket.socket:
            raise OSError("unreachable")

        ConnectHandler.allowed_hosts = frozenset({"openrouter.ai"})
        ConnectHandler.connector = staticmethod(fail_connect)
        try:
            with ThreadingServer(("127.0.0.1", 0), ConnectHandler) as server:
                worker = threading.Thread(target=server.handle_request)
                worker.start()
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall(b"CONNECT openrouter.ai:443 HTTP/1.1\r\n\r\n")
                    response = client.recv(4096)
                worker.join(2)
            self.assertTrue(response.startswith(b"HTTP/1.1 403"), response)
        finally:
            ConnectHandler.connector = staticmethod(original)

    def test_mismatched_sni_never_reaches_upstream(self) -> None:
        original = ConnectHandler.connector
        proxy_end, observer_end = socket.socketpair()

        def local_connect(_host: str) -> socket.socket:
            return proxy_end

        ConnectHandler.allowed_hosts = frozenset({"openrouter.ai"})
        ConnectHandler.connector = staticmethod(local_connect)
        try:
            with ThreadingServer(("127.0.0.1", 0), ConnectHandler) as server:
                worker = threading.Thread(target=server.handle_request)
                worker.start()
                with socket.create_connection(server.server_address, timeout=2) as client:
                    client.sendall(b"CONNECT openrouter.ai:443 HTTP/1.1\r\n\r\n")
                    response = client.recv(4096)
                    self.assertTrue(response.startswith(b"HTTP/1.1 200"), response)
                    client.sendall(self.client_hello("example.com"))
                    client.recv(4096)
                worker.join(2)
            observer_end.settimeout(1)
            self.assertEqual(observer_end.recv(1), b"")
        finally:
            ConnectHandler.connector = staticmethod(original)
            proxy_end.close()
            observer_end.close()


if __name__ == "__main__":
    if sys.argv[1:] == ["--self-test"]:
        sys.argv[1:] = []
        unittest.main()
    elif sys.argv[1:]:
        raise SystemExit("usage: egress-proxy.py [--self-test]")
    else:
        serve()
