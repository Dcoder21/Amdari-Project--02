"""Shared helper for V-APP-04: reject URLs that resolve to internal/private
network destinations before the app ever issues a server-side request to
them. Resolves the hostname and checks every returned address rather than
just the literal host string, since a hostname can resolve to a private IP
(including cloud metadata endpoints) just as easily as a literal IP can.

Deliberately duplicated from payments-api/app/ssrf_guard.py: the two
services build from separate Docker contexts, same pattern as the test
fixture duplication in tests/conftest.py.

This is a best-effort check, not a complete SSRF defence (DNS can still
change between this check and the actual request — true defence-in-depth
would also need egress network policy at the infrastructure layer, which is
Week 2 scope). It is enough to close the direct exploit path demonstrated in
the Week 1 findings.
"""
import ipaddress
import socket
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}


def is_safe_external_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
    except ValueError:
        return False

    if parsed.scheme not in ALLOWED_SCHEMES or not parsed.hostname:
        return False

    try:
        addr_infos = socket.getaddrinfo(parsed.hostname, None)
    except socket.gaierror:
        return False

    if not addr_infos:
        return False

    for _family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip = ipaddress.ip_address(sockaddr[0])
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        ):
            return False

    return True
