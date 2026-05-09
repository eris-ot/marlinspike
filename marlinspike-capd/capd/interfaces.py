"""Interface enumeration.

Returns physical-looking NICs by default. Operators in the workbench
don't want to pick from a 30-line list of docker/veth/wireguard
interfaces; the `include_virtual=True` toggle gives them the full set
when they actually need it.
"""

from __future__ import annotations

import re
import socket
from dataclasses import asdict, dataclass
from typing import Iterable

import psutil

# Interface name patterns we treat as "virtual" — hidden by default. These
# come from real engagement laptops where the actual physical NIC is
# drowned out by container/VPN bookkeeping.
_VIRTUAL_PATTERNS: tuple[re.Pattern, ...] = tuple(
    re.compile(p) for p in (
        r"^lo\d*$",
        r"^docker\d*$",
        r"^br-[0-9a-f]+$",
        r"^veth.*$",
        r"^tun\d*$",
        r"^tap\d*$",
        r"^wg\d*$",
        r"^utun\d*$",          # macOS VPN
        r"^awdl\d*$",          # Apple Wireless Direct
        r"^llw\d*$",           # Apple Low-Latency WLAN
        r"^anpi\d*$",          # Apple network plumbing
        r"^bridge\d*$",        # macOS bridge
        r"^tailscale\d*$",
        r"^zt[0-9a-z]+$",      # ZeroTier
        r"^gif\d*$",           # generic tunnel
        r"^stf\d*$",           # 6to4 tunnel
        r"^ap\d*$",            # macOS AirPlay
        r"^en[0-9]+\.\d+$",    # vlan subinterfaces — keep separate from physical
    )
)

# Loopback, separately classified so it can be shown when 'include_virtual'.
_LOOPBACK_PATTERN = re.compile(r"^lo\d*$")


@dataclass
class Interface:
    name: str
    mac: str | None
    ips: list[str]
    is_up: bool
    is_loopback: bool
    is_virtual: bool
    mtu: int | None
    speed_mbps: int | None  # None when unknown

    def to_dict(self) -> dict:
        return asdict(self)


def _is_virtual(name: str) -> bool:
    return any(p.match(name) for p in _VIRTUAL_PATTERNS)


def _is_loopback(name: str) -> bool:
    return bool(_LOOPBACK_PATTERN.match(name))


def list_interfaces(include_virtual: bool = False) -> list[dict]:
    """Enumerate NICs visible to capd.

    Hides virtual interfaces by default. The `any` pseudo-device
    (Linux-only) is appended last when `include_virtual=False` so users
    can pick it without scrolling through a virtual-interface list.
    """
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    out: list[Interface] = []
    for name, addr_list in addrs.items():
        loopback = _is_loopback(name)
        virtual = _is_virtual(name) and not loopback
        if not include_virtual and (loopback or virtual):
            continue

        mac: str | None = None
        ips: list[str] = []
        for a in addr_list:
            if a.family == psutil.AF_LINK:
                mac = a.address or None
            elif a.family in (socket.AF_INET, socket.AF_INET6):
                # Strip zone-id suffix from link-local v6 addresses.
                addr = (a.address or "").split("%")[0]
                if addr:
                    ips.append(addr)

        st = stats.get(name)
        out.append(Interface(
            name=name,
            mac=mac,
            ips=ips,
            is_up=bool(st.isup) if st else False,
            is_loopback=loopback,
            is_virtual=virtual,
            mtu=int(st.mtu) if st and st.mtu else None,
            speed_mbps=int(st.speed) if st and st.speed else None,
        ))

    out.sort(key=lambda i: (not i.is_up, i.is_virtual, i.is_loopback, i.name))

    # `any` pseudo-device is Linux-only; we surface it always when not
    # filtering, so the operator can pick "all interfaces" without
    # scrolling to find it.
    if not include_virtual:
        out.append(Interface(
            name="any",
            mac=None,
            ips=[],
            is_up=True,
            is_loopback=False,
            is_virtual=False,
            mtu=None,
            speed_mbps=None,
        ))

    return [i.to_dict() for i in out]


def find_interface(name: str) -> dict | None:
    for iface in list_interfaces(include_virtual=True):
        if iface["name"] == name:
            return iface
    if name == "any":
        return {
            "name": "any", "mac": None, "ips": [], "is_up": True,
            "is_loopback": False, "is_virtual": False, "mtu": None,
            "speed_mbps": None,
        }
    return None


def format_table(ifaces: Iterable[dict]) -> str:
    """Pretty-print for the CLI."""
    rows = list(ifaces)
    if not rows:
        return "(no interfaces)"
    name_w = max(len(r["name"]) for r in rows)
    out = []
    for r in rows:
        flags = []
        if r["is_loopback"]:
            flags.append("loop")
        if r["is_virtual"]:
            flags.append("virt")
        if not r["is_up"]:
            flags.append("down")
        flag_s = ",".join(flags) or "-"
        ip_s = ", ".join(r["ips"]) if r["ips"] else "-"
        mac = r["mac"] or "-"
        out.append(f"  {r['name']:<{name_w}}  {mac:<17}  {flag_s:<10}  {ip_s}")
    return "\n".join(out)
