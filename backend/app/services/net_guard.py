"""SSRF / platform-protection guard for scan and tool targets.

Blocks what would let a scan reach infrastructure that could compromise the
platform itself or its host: cloud-metadata endpoints, loopback, link-local,
private/internal IP ranges (RFC1918 etc. — this platform runs on a VPS
alongside other internal-network infrastructure, so a scan resolving into
that range is reaching the host's own network, not a customer's target),
this deployment's own service containers, and this deployment's own public
domain (so the platform can't be pointed at itself). Extra ranges/domains for
a given deployment are configured via PLATFORM_BLOCKED_CIDRS and
PLATFORM_BLOCKED_DOMAINS.
"""
from __future__ import annotations

import ipaddress
import logging
import os
import re
import socket

log = logging.getLogger(__name__)

# Shared domain-format allowlist — anything starting with '-', containing
# whitespace, or holding shell/flag metacharacters fails this and is
# rejected before ever reaching a subprocess argv.
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)

# Docker Compose service names for this deployment's own infrastructure.
# Resolved fresh on each check (not cached) since container IPs can change
# across restarts/rebuilds.
_PLATFORM_HOSTNAMES = {
    "postgres", "redis", "minio", "backend",
    "worker", "heavy-worker", "investigation-worker",
    "frontend", "caddy",
}

# Cloud metadata hostnames blocked by name — some clouds route these by name
# rather than a fixed IP.
_METADATA_HOSTNAMES = {"metadata.google.internal", "metadata.goog"}

# AWS IMDSv2 IPv6 metadata address — a ULA (fd00::/8), not covered by
# ipaddress.is_link_local (which only covers fe80::/10).
_METADATA_IPV6 = {"fd00:ec2::254"}

# Blocked outright regardless of DNS resolution — "localhost" never leaves
# the box it's typed on, so there's no legitimate scan target behind it.
_EXTRA_BLOCKED_HOSTNAMES = {"localhost"}


def _platform_ips() -> set[str]:
    ips: set[str] = set()
    for name in _PLATFORM_HOSTNAMES:
        try:
            infos = socket.getaddrinfo(name, None)
        except socket.gaierror:
            continue
        for info in infos:
            ips.add(info[4][0])
    return ips


def _extra_blocked_networks() -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    raw = os.environ.get("PLATFORM_BLOCKED_CIDRS", "")
    nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def _blocked_domains() -> set[str]:
    """This deployment's own public domain(s) — e.g. the domain the app is
    hosted on. Suffix-matched, so blocking 'example.com' also blocks
    'sub.example.com'."""
    raw = os.environ.get("PLATFORM_BLOCKED_DOMAINS", "")
    return {part.strip().lower() for part in raw.split(",") if part.strip()}


def _is_blocked_domain(host: str, blocked_domains: set[str]) -> bool:
    return any(host == d or host.endswith(f".{d}") for d in blocked_domains)


def _check_one(
    host: str,
    platform_ips: set[str],
    extra_nets: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    blocked_domains: set[str],
) -> None:
    lowered = host.strip().lower().rstrip(".")
    if lowered in _PLATFORM_HOSTNAMES or lowered in _METADATA_HOSTNAMES:
        raise ValueError(f"target '{host}' is not permitted (platform-protected)")
    if lowered in _EXTRA_BLOCKED_HOSTNAMES:
        raise ValueError(f"target '{host}' is not permitted")
    if _is_blocked_domain(lowered, blocked_domains):
        raise ValueError(
            f"target '{host}' is not permitted (this platform's own domain)"
        )
    # A subdomain label starting with '-' would be parsed as a flag by nmap/
    # testssl, which take the host as a bare positional argv token (not the
    # value of a flag). subfinder/amass/bbot ingestion doesn't reject this
    # shape, so it's caught here instead, at the single chokepoint every
    # active-scan adapter already calls through.
    if host.strip().startswith("-"):
        raise ValueError(f"target '{host}' is not permitted (looks like a flag)")

    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return

    for info in infos:
        addr = info[4][0].split("%", 1)[0]  # strip IPv6 zone id if present
        if addr in _METADATA_IPV6:
            raise ValueError(
                f"target '{host}' resolves to {addr}, a cloud metadata address — "
                "not permitted"
            )
        ip = ipaddress.ip_address(addr)
        # is_private covers loopback, link-local, and RFC1918/other
        # non-globally-routable ranges in one check — this platform runs on
        # a VPS, so anything private is this host's own internal network,
        # not a customer's target.
        if ip.is_private or ip.is_loopback or ip.is_link_local:
            raise ValueError(
                f"target '{host}' resolves to {addr}, which is a private/internal "
                "address (this includes loopback, link-local, and cloud metadata "
                "endpoints) — not permitted"
            )
        if addr in platform_ips:
            raise ValueError(
                f"target '{host}' resolves to {addr}, which is this platform's own "
                "infrastructure — not permitted"
            )
        for net in extra_nets:
            if ip in net:
                raise ValueError(
                    f"target '{host}' resolves to {addr}, which is in a "
                    "platform-blocked range — not permitted"
                )


def assert_target_allowed(host: str) -> None:
    """Raise ValueError if ``host`` would let a scan reach the platform
    itself, its private/internal network, or a cloud-metadata endpoint.
    Resolves the host and checks every returned address. Does not raise on
    an unresolvable host — that's the tool's own DNS error to surface, not a
    guard concern.
    """
    _check_one(host, _platform_ips(), _extra_blocked_networks(), _blocked_domains())


def filter_allowed_hosts(hosts: list[str]) -> list[str]:
    """Batch form for stages that scan many hosts at once (naabu/nmap/
    gowitness). Silently drops disallowed hosts rather than aborting the
    whole stage over one bad entry — the primary gate is at scan/target
    creation; this is the defensive backstop for hosts a later recon stage
    (subfinder/amass/bbot) discovered on its own.
    """
    platform_ips = _platform_ips()
    extra_nets = _extra_blocked_networks()
    blocked_domains = _blocked_domains()
    allowed = []
    for host in hosts:
        try:
            _check_one(host, platform_ips, extra_nets, blocked_domains)
            allowed.append(host)
        except ValueError as e:
            log.warning("net_guard: dropping host from active-scan batch: %s", e)
    return allowed
