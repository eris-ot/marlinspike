"""BPF filter validation via libpcap ctypes.

We compile filters with `pcap_compile_nopcap`, which doesn't need an
open interface — operators get a syntax check the moment they tab out
of the filter field, instead of a daemon that exits 200ms after
clicking start. libpcap is already on the system because dumpcap
depends on it, so no new build dep.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import sys
from typing import NamedTuple

# Common DLT values. We default to EN10MB (Ethernet) since OT engagements
# are essentially always on Ethernet/SPAN. Operators capturing Wi-Fi
# directly would need a different DLT; out of scope for v1.
DLT_EN10MB = 1
DLT_LINUX_SLL = 113   # Linux cooked v1, used for the `any` pseudo-device
DLT_LINUX_SLL2 = 276  # Linux cooked v2

PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF


class _BpfProgram(ctypes.Structure):
    _fields_ = [
        ("bf_len", ctypes.c_uint),
        ("bf_insns", ctypes.c_void_p),
    ]


class ValidationResult(NamedTuple):
    ok: bool
    error: str | None


_lib: ctypes.CDLL | None = None
_load_error: str | None = None


def _load_libpcap() -> ctypes.CDLL:
    """Locate and bind libpcap. Cached after first call."""
    global _lib, _load_error
    if _lib is not None:
        return _lib
    if _load_error is not None:
        raise OSError(_load_error)

    candidates: list[str] = []
    found = ctypes.util.find_library("pcap")
    if found:
        candidates.append(found)
    if sys.platform == "darwin":
        candidates += [
            "/usr/lib/libpcap.A.dylib",
            "/usr/lib/libpcap.dylib",
            "/opt/homebrew/lib/libpcap.dylib",
        ]
    else:
        candidates += [
            "libpcap.so.1",
            "libpcap.so.0.8",
            "libpcap.so",
            "/usr/lib/x86_64-linux-gnu/libpcap.so.1",
            "/usr/lib/aarch64-linux-gnu/libpcap.so.1",
            "/usr/lib64/libpcap.so.1",
        ]

    last_err: str | None = None
    for path in candidates:
        try:
            lib = ctypes.CDLL(path)
        except OSError as exc:
            last_err = str(exc)
            continue

        lib.pcap_compile_nopcap.argtypes = [
            ctypes.c_int,                # snaplen
            ctypes.c_int,                # linktype
            ctypes.POINTER(_BpfProgram), # program out
            ctypes.c_char_p,             # filter str
            ctypes.c_int,                # optimize
            ctypes.c_uint,               # netmask
        ]
        lib.pcap_compile_nopcap.restype = ctypes.c_int

        lib.pcap_freecode.argtypes = [ctypes.POINTER(_BpfProgram)]
        lib.pcap_freecode.restype = None

        lib.pcap_lib_version.argtypes = []
        lib.pcap_lib_version.restype = ctypes.c_char_p

        _lib = lib
        return lib

    _load_error = f"libpcap not found (tried: {', '.join(candidates)}; last error: {last_err})"
    raise OSError(_load_error)


def libpcap_version() -> str:
    lib = _load_libpcap()
    raw = lib.pcap_lib_version()
    return raw.decode("ascii", errors="replace") if raw else "unknown"


def validate(filter_str: str, link_type: int = DLT_EN10MB, snaplen: int = 65535) -> ValidationResult:
    """Compile a BPF filter without an interface. Returns (ok, error)."""
    if filter_str is None:
        return ValidationResult(False, "filter is None")
    # Empty filter is valid — captures everything.
    s = filter_str.strip()
    if not s:
        return ValidationResult(True, None)

    try:
        lib = _load_libpcap()
    except OSError as exc:
        return ValidationResult(False, f"libpcap unavailable: {exc}")

    program = _BpfProgram()
    rc = lib.pcap_compile_nopcap(
        snaplen,
        link_type,
        ctypes.byref(program),
        s.encode("utf-8"),
        1,  # optimize
        PCAP_NETMASK_UNKNOWN,
    )
    if rc < 0:
        # pcap_compile_nopcap doesn't expose pcap_geterr because there's
        # no pcap_t; we return a generic message. Most BPF errors are
        # obvious from re-reading the filter (unbalanced parens, unknown
        # protocol name, bad port number).
        return ValidationResult(False, "BPF compile failed (check syntax, protocol/port names, parens)")
    lib.pcap_freecode(ctypes.byref(program))
    return ValidationResult(True, None)
