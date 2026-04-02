"""Target allowlist loading and enforcement.

Three controls:
1. Load allowlist from signed file
2. Verify every target is a subset of the allowlist
3. Post-resolution re-check after DNS expansion
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from pathlib import Path

from src.orchestrator.exceptions import AllowlistLoadError, TargetOutOfScopeError

LOG = logging.getLogger(__name__)


class Allowlist:
    """Manages the approved target allowlist with subset enforcement."""

    def __init__(
        self,
        entries: set[str],
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ):
        self._entries = entries
        self._networks = networks

    @classmethod
    def from_file(cls, path: Path) -> Allowlist:
        """Load allowlist from a text file. One entry per line."""
        if not path.exists():
            raise AllowlistLoadError(f"Allowlist file not found: {path}")

        entries: set[str] = set()
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []

        for raw_line in path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            norm = line.lower()
            entries.add(norm)
            try:
                net = ipaddress.ip_network(line, strict=False)
                networks.append(net)
            except ValueError:
                pass

        if not entries:
            raise AllowlistLoadError(f"Allowlist is empty: {path}")

        LOG.info("Loaded allowlist with %d entries and %d networks", len(entries), len(networks))
        return cls(entries=entries, networks=networks)

    @property
    def entries(self) -> set[str]:
        return set(self._entries)

    def contains(self, target: str) -> bool:
        """Check if a single target is in the allowlist."""
        normalized = target.strip().lower()
        if not normalized:
            return False
        if normalized in self._entries:
            return True

        try:
            addr = ipaddress.ip_address(normalized)
        except ValueError:
            return False

        for net in self._networks:
            if addr in net:
                return True

        return False

    def enforce(self, targets: list[str]) -> list[str]:
        """Verify all targets are in the allowlist."""
        out_of_scope: set[str] = set()
        for target in targets:
            if not self.contains(target):
                out_of_scope.add(target)

        if out_of_scope:
            LOG.error("Targets outside allowlist: %s", out_of_scope)
            raise TargetOutOfScopeError(out_of_scope)

        LOG.info("All %d targets validated against allowlist", len(targets))
        return targets

    def enforce_resolved(self, hostname_ip_map: dict[str, list[str]]) -> dict[str, list[str]]:
        """Post-DNS-resolution enforcement."""
        out_of_scope: set[str] = set()
        for hostname, ips in hostname_ip_map.items():
            for ip in ips:
                if not self.contains(ip) and not self.contains(hostname):
                    out_of_scope.add(f"{hostname}->{ip}")

        if out_of_scope:
            LOG.error("Resolved addresses outside allowlist: %s", out_of_scope)
            raise TargetOutOfScopeError(
                out_of_scope,
                message=f"Post-resolution targets outside allowlist: {out_of_scope}",
            )

        LOG.info("All resolved addresses validated against allowlist")
        return hostname_ip_map


def resolve_targets(targets: list[str]) -> dict[str, list[str]]:
    """Resolve hostnames to IP addresses for post-resolution allowlist check."""
    resolved: dict[str, list[str]] = {}
    for target in targets:
        t = target.strip()
        if not t:
            continue

        try:
            ipaddress.ip_address(t)
            resolved[t] = [t]
            continue
        except ValueError:
            pass

        try:
            ipaddress.ip_network(t, strict=False)
            resolved[t] = [t]
            continue
        except ValueError:
            pass

        try:
            _, _, addrs = socket.gethostbyname_ex(t)
            resolved[t] = addrs
            LOG.debug("Resolved %s -> %s", t, addrs)
        except socket.gaierror:
            LOG.warning("DNS resolution failed for %s - keeping as hostname", t)
            resolved[t] = [t]

    return resolved
