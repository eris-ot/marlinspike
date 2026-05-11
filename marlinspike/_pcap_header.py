"""Pure-Python PCAP / PCAPNG header reader.

Returns the basic capture metadata (packet count, duration, first/last
timestamps, link type) that `validate_pcap()` previously got from
`capinfos` or `tshark`. Stdlib only — no scapy, no dpkt, no libpcap.

Reads only record/block headers, not packet payloads, so it's fast on
large captures (one 4 KiB read per ~250 packets in the common case).

Supports:
  - Classic PCAP, both byte orders, microsecond and nanosecond resolution
  - PCAPNG with a single Section Header Block (the format multi-section
    case is rare in OT/ICS captures; we'd misreport duration on those and
    the result is documented as best-effort)

Does NOT verify packet integrity, parse link-layer payloads, or
decompress anything — just walks block/record headers.
"""

from __future__ import annotations

import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Optional


# Classic PCAP magic numbers
_PCAP_MAGIC_LE_US = 0xA1B2C3D4
_PCAP_MAGIC_BE_US = 0xD4C3B2A1
_PCAP_MAGIC_LE_NS = 0xA1B23C4D
_PCAP_MAGIC_BE_NS = 0x4D3CB2A1

# PCAPNG block types
_BLOCK_SHB = 0x0A0D0D0A  # Section Header Block
_BLOCK_IDB = 0x00000001  # Interface Description Block
_BLOCK_EPB = 0x00000006  # Enhanced Packet Block
_BLOCK_SPB = 0x00000003  # Simple Packet Block
_BLOCK_PB = 0x00000002   # Packet Block (obsolete, still seen)

# PCAPNG SHB byte-order magic
_SHB_BOM_LE = 0x1A2B3C4D
_SHB_BOM_BE = 0x4D3C2B1A


# LINKTYPE_* → human label. Covers everything we'd see in OT/ICS work
# plus the common IT ones. Mirrors tshark/capinfos labels where they
# agree; falls back to a numeric "LINKTYPE_n" for unknowns.
_LINKTYPE_NAMES = {
    0: "BSD loopback",
    1: "Ethernet",
    9: "PPP",
    105: "IEEE 802.11",
    113: "Linux cooked v1",
    127: "IEEE 802.11 radiotap",
    143: "DOCSIS",
    147: "DLT_USER0",
    148: "DLT_USER1",
    195: "IEEE 802.15.4 with FCS",
    228: "IPv4",
    229: "IPv6",
    276: "Linux cooked v2",
}


@dataclass
class CaptureSummary:
    packet_count: int
    duration_seconds: float
    start_ts: Optional[float]
    end_ts: Optional[float]
    link_type: str
    snaplen: int
    format: str  # "pcap" | "pcapng"

    def to_capinfos_fields(self) -> dict[str, str]:
        """Map to the same field names `validate_pcap` parses from
        `capinfos -T -M` output, so the existing call site can use this
        as a drop-in replacement."""
        return {
            "Number of packets": str(self.packet_count),
            "Capture duration (seconds)": f"{self.duration_seconds:.6f}",
            "First packet time": _iso(self.start_ts),
            "Last packet time": _iso(self.end_ts),
            "Encapsulation": self.link_type,
        }


def read_capture_summary(path: str) -> CaptureSummary:
    """Read a PCAP or PCAPNG file and return its summary.

    Raises ValueError if the file isn't a recognised capture format.
    Lets IOError propagate for filesystem issues.
    """
    with open(path, "rb") as f:
        head = f.read(4)
        if len(head) < 4:
            raise ValueError("file is too short to be a capture")

        magic = struct.unpack(">I", head)[0]

        if magic == _BLOCK_SHB:
            return _read_pcapng(f)

        # Otherwise treat as classic PCAP — magic is the first 4 bytes.
        f.seek(0)
        return _read_pcap(f)


def _read_pcap(f: BinaryIO) -> CaptureSummary:
    header = f.read(24)
    if len(header) < 24:
        raise ValueError("pcap file is truncated (missing global header)")

    raw_magic = struct.unpack("<I", header[:4])[0]
    if raw_magic == _PCAP_MAGIC_LE_US:
        endian, ts_divisor = "<", 1_000_000
    elif raw_magic == _PCAP_MAGIC_BE_US:
        endian, ts_divisor = ">", 1_000_000
    elif raw_magic == _PCAP_MAGIC_LE_NS:
        endian, ts_divisor = "<", 1_000_000_000
    elif raw_magic == _PCAP_MAGIC_BE_NS:
        endian, ts_divisor = ">", 1_000_000_000
    else:
        raise ValueError(f"not a recognised pcap magic: 0x{raw_magic:08x}")

    _magic, _vmajor, _vminor, _thiszone, _sigfigs, snaplen, network = struct.unpack(
        endian + "IHHIIII", header
    )

    link_type = _LINKTYPE_NAMES.get(network, f"LINKTYPE_{network}")

    packet_count = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    rec_fmt = endian + "IIII"  # ts_sec, ts_subsec, incl_len, orig_len
    rec_size = 16

    while True:
        rec_hdr = f.read(rec_size)
        if len(rec_hdr) < rec_size:
            break  # EOF or partial record — we count what we got.
        ts_sec, ts_subsec, incl_len, _orig_len = struct.unpack(rec_fmt, rec_hdr)

        # Cap incl_len defensively — a malformed file could claim a huge
        # payload and we don't want to seek to negative or astronomical offsets.
        if incl_len > snaplen * 4 + 1 << 20 and incl_len > 1 << 24:
            raise ValueError(
                f"pcap record claims absurd payload length {incl_len} — file corrupt?"
            )

        ts = ts_sec + ts_subsec / ts_divisor
        if first_ts is None:
            first_ts = ts
        last_ts = ts
        packet_count += 1

        try:
            f.seek(incl_len, os.SEEK_CUR)
        except OSError:
            # Negative seek or past EOF — treat as truncation, stop counting.
            break

    duration = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0.0

    return CaptureSummary(
        packet_count=packet_count,
        duration_seconds=duration,
        start_ts=first_ts,
        end_ts=last_ts,
        link_type=link_type,
        snaplen=snaplen,
        format="pcap",
    )


def _read_pcapng(f: BinaryIO) -> CaptureSummary:
    """Walk PCAPNG blocks. We assume one Section Header Block at the
    start; multi-section files are rare in OT/ICS work and we'd
    misreport duration if the byte order changes mid-file."""
    f.seek(0)

    # First read SHB to learn byte order.
    raw = f.read(12)
    if len(raw) < 12:
        raise ValueError("pcapng file is truncated (missing SHB)")

    block_type, block_len, bom = struct.unpack("<III", raw)
    if block_type != _BLOCK_SHB:
        raise ValueError("pcapng file does not start with SHB")

    if bom == _SHB_BOM_LE:
        endian = "<"
    elif bom == _SHB_BOM_BE:
        endian = ">"
        block_len = struct.unpack(">I", struct.pack("<I", block_len))[0]
    else:
        raise ValueError(f"unrecognised pcapng byte-order magic: 0x{bom:08x}")

    # Skip rest of SHB.
    f.seek(block_len, 0)

    # Per-interface state: timestamp resolution (defaults to 10^-6 seconds)
    # and link-layer type. PCAPNG can have multiple interfaces; we use a
    # list indexed by interface_id (the order IDBs appear).
    if_resolutions: list[int] = []   # divisor for each interface
    if_linktypes: list[int] = []     # network link type for each interface
    snaplen_max = 0

    packet_count = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    while True:
        header = f.read(8)
        if len(header) < 8:
            break

        if endian == "<":
            block_type, block_len = struct.unpack("<II", header)
        else:
            block_type, block_len = struct.unpack(">II", header)

        if block_len < 12 or block_len % 4 != 0:
            # PCAPNG blocks are 32-bit aligned with length >= 12. Anything
            # else means we've lost sync or the file is corrupt.
            break

        body_len = block_len - 12  # block_type + block_len + trailing block_len
        body = f.read(body_len)
        trailing = f.read(4)
        if len(body) < body_len or len(trailing) < 4:
            break

        if block_type == _BLOCK_IDB:
            # Interface Description Block: linktype (2B), reserved (2B), snaplen (4B), options...
            if len(body) >= 8:
                if endian == "<":
                    linktype, _res, idb_snaplen = struct.unpack("<HHI", body[:8])
                else:
                    linktype, _res, idb_snaplen = struct.unpack(">HHI", body[:8])
                if_linktypes.append(linktype)
                if_resolutions.append(1_000_000)  # microsecond default
                snaplen_max = max(snaplen_max, idb_snaplen)
                # Walk options to find if_tsresol (option code 9).
                opt_pos = 8
                while opt_pos + 4 <= len(body):
                    if endian == "<":
                        opt_code, opt_len = struct.unpack("<HH", body[opt_pos:opt_pos + 4])
                    else:
                        opt_code, opt_len = struct.unpack(">HH", body[opt_pos:opt_pos + 4])
                    if opt_code == 0:
                        break  # end-of-options
                    if opt_code == 9 and opt_len >= 1:
                        tsresol = body[opt_pos + 4]
                        if tsresol & 0x80:
                            # Base 2: 2 ^ (low 7 bits) units per second.
                            if_resolutions[-1] = 1 << (tsresol & 0x7F)
                        else:
                            # Base 10: 10 ^ tsresol units per second.
                            if_resolutions[-1] = 10 ** tsresol
                    # 32-bit aligned advance.
                    opt_pos += 4 + ((opt_len + 3) & ~3)

        elif block_type == _BLOCK_EPB:
            if len(body) >= 20:
                if endian == "<":
                    if_id, ts_high, ts_low, _captured_len, _orig_len = struct.unpack(
                        "<IIIII", body[:20]
                    )
                else:
                    if_id, ts_high, ts_low, _captured_len, _orig_len = struct.unpack(
                        ">IIIII", body[:20]
                    )
                if 0 <= if_id < len(if_resolutions):
                    divisor = if_resolutions[if_id]
                else:
                    divisor = 1_000_000
                ts_raw = (ts_high << 32) | ts_low
                ts = ts_raw / divisor
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
                packet_count += 1

        elif block_type == _BLOCK_PB:
            # Obsolete Packet Block — has timestamps. Layout differs from EPB.
            if len(body) >= 20:
                if endian == "<":
                    _if_id, _drops, ts_high, ts_low = struct.unpack(
                        "<HHII", body[:12]
                    )
                else:
                    _if_id, _drops, ts_high, ts_low = struct.unpack(
                        ">HHII", body[:12]
                    )
                ts_raw = (ts_high << 32) | ts_low
                ts = ts_raw / 1_000_000  # legacy default
                if first_ts is None:
                    first_ts = ts
                last_ts = ts
                packet_count += 1

        elif block_type == _BLOCK_SPB:
            # Simple Packet Block: no timestamp. Counts but doesn't update time.
            packet_count += 1

        # else: skip unknown block type. PCAPNG is forward-compatible — readers
        # are required to skip unrecognised blocks.

    duration = (last_ts - first_ts) if (first_ts is not None and last_ts is not None) else 0.0

    # Use the first interface's link type as the headline (consistent with
    # how capinfos reports it for single-interface captures).
    if if_linktypes:
        link_label = _LINKTYPE_NAMES.get(if_linktypes[0], f"LINKTYPE_{if_linktypes[0]}")
    else:
        link_label = "Unknown"

    return CaptureSummary(
        packet_count=packet_count,
        duration_seconds=duration,
        start_ts=first_ts,
        end_ts=last_ts,
        link_type=link_label,
        snaplen=snaplen_max,
        format="pcapng",
    )


def _iso(ts: Optional[float]) -> str:
    if ts is None:
        return ""
    # Match the format `capinfos -T -M` emits.
    import datetime
    return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M:%S.%f UTC"
    )
