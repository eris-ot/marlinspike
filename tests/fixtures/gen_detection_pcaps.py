"""Generate deterministic detection-scenario PCAPs for MarlinSpike.

Each scenario = a small benign OT/IT baseline plus (optionally) one injected
malicious pattern engineered to trip a *specific* engine detector at a known
severity. Thresholds are taken from marlinspike/engine.py:

  - beacon: _compute_beacon_score_from_timestamps needs >=10 timestamps,
    deltas > 0.01s, median delta >= 0.1s. A perfectly periodic series to a
    globally-routable IP on a non-OT/non-well-known port -> score ~1.0 ->
    C2_BEACONING CRITICAL (>0.7).
  - dns exfil: dns_entropy > 4.0 AND >50 unique subdomains under one base
    domain -> C2_DNS_EXFIL CRITICAL.
  - ics external: an OT-classified device talking to a public IP ->
    ICS_EXTERNAL_COMMS / EXTERNAL_IPS_OBSERVED.
  - port scan: one source hitting many ports on one target.

Run:  python3 tests/fixtures/gen_detection_pcaps.py [outdir]
Default outdir: tests/fixtures/pcaps/
"""

from __future__ import annotations

import os
import struct
import sys

from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
from scapy.layers.dns import DNS, DNSQR

# ── address plan ──────────────────────────────────────────────────────────
LAN = "10.10.0."
HMI = LAN + "50"          # operator workstation (IT-ish)
PLC = LAN + "20"          # Modbus PLC (OT, Purdue L1/L2)
ENG = LAN + "30"          # engineering workstation
DNS_SRV = LAN + "2"       # internal resolver
WEB = LAN + "10"          # internal web/historian
BEACON_HOST = LAN + "66"  # compromised host (C2 beacon source)
EXFIL_HOST = LAN + "77"   # compromised host (DNS exfil source)
SCANNER = LAN + "99"      # internal scanner
PUBLIC_C2 = "93.184.216.34"   # globally-routable (is_global == True)

MAC = "02:00:00:00:00:%02x"


def _eth(src_last: int, dst_last: int):
    return Ether(src=MAC % src_last, dst=MAC % dst_last)


def _modbus(tx: int, unit: int, func: int, data: bytes) -> bytes:
    """Modbus/TCP MBAP + PDU."""
    pdu = bytes([func]) + data
    return struct.pack(">HHHB", tx, 0, len(pdu) + 1, unit) + pdu


def baseline(t0: float = 0.0):
    """Benign traffic every scenario shares: DNS lookups, an HTTP fetch, and
    read-only Modbus polling HMI -> PLC. Should produce no C2/external risk."""
    pkts = []
    t = t0
    # Normal DNS: HMI resolves a couple of low-entropy names.
    for name in (b"intranet.plant.local", b"historian.plant.local"):
        q = (_eth(50, 2) / IP(src=HMI, dst=DNS_SRV) / UDP(sport=40000, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=name)))
        q.time = t
        pkts.append(q)
        t += 0.05
    # Normal HTTP: HMI -> internal web.
    syn = _eth(50, 10) / IP(src=HMI, dst=WEB) / TCP(sport=44001, dport=80, flags="S")
    syn.time = t
    sa = _eth(10, 50) / IP(src=WEB, dst=HMI) / TCP(sport=80, dport=44001, flags="SA")
    sa.time = t + 0.01
    get = (_eth(50, 10) / IP(src=HMI, dst=WEB) / TCP(sport=44001, dport=80, flags="PA")
           / Raw(b"GET / HTTP/1.1\r\nHost: historian\r\n\r\n"))
    get.time = t + 0.02
    pkts += [syn, sa, get]
    t += 0.1
    # Read-only Modbus polling: HMI -> PLC, function 3 (read holding regs).
    for i in range(6):
        rq = (_eth(50, 20) / IP(src=HMI, dst=PLC) / TCP(sport=45000, dport=502, flags="PA")
              / Raw(_modbus(i, 1, 3, struct.pack(">HH", 0, 10))))
        rq.time = t
        rp = (_eth(20, 50) / IP(src=PLC, dst=HMI) / TCP(sport=502, dport=45000, flags="PA")
              / Raw(_modbus(i, 1, 3, bytes([20]) + b"\x00" * 20)))
        rp.time = t + 0.01
        pkts += [rq, rp]
        t += 1.0
    return pkts


def scen_clean():
    return baseline()


def scen_c2_beacon():
    """BEACON_HOST -> PUBLIC_C2:4444 every 30.0s x 24 (jitter 0).
    Expect: C2_BEACONING CRITICAL + external-comms indicators."""
    pkts = baseline()
    interval, count, port = 30.0, 24, 4444
    # One packet per interval -> pure 30.0s inter-arrival deltas, jitter 0,
    # cluster_fraction 1.0 -> beacon_score ~1.0 -> CRITICAL (>0.7) to a
    # globally-routable IP. A handshake triad would mix 0.03s/30s deltas
    # and depress the score to HIGH.
    for i in range(count):
        beacon = (_eth(66, 1) / IP(src=BEACON_HOST, dst=PUBLIC_C2)
                  / UDP(sport=49200, dport=port) / Raw(b"\x00" * 16))
        beacon.time = 100.0 + i * interval
        pkts.append(beacon)
    return pkts


def scen_dns_exfil():
    """EXFIL_HOST -> DNS_SRV: 64 unique 24-hex-char subdomains under one base.
    Expect: C2_DNS_EXFIL CRITICAL (entropy > 4.0, unique > 50)."""
    pkts = baseline()
    base = "exfil.example.com"
    t = 50.0
    # Deterministic high-entropy labels (LCG). Base36 alphabet (36 symbols)
    # so per-label Shannon entropy exceeds the strict > 4.0 CRITICAL
    # threshold; a 16-symbol hex alphabet caps at exactly 4.0 and only
    # trips the lower C2_DNS_HIGH_ENTROPY tier.
    alpha = "abcdefghijklmnopqrstuvwxyz0123456789"
    seed = 0x1234ABCD
    for i in range(64):
        chars = []
        for _ in range(28):
            seed = (1103515245 * seed + 12345) & 0x7FFFFFFF
            chars.append(alpha[seed % len(alpha)])
        qname = "".join(chars) + "." + base
        q = (_eth(77, 2) / IP(src=EXFIL_HOST, dst=DNS_SRV) / UDP(sport=51000 + i, dport=53)
             / DNS(rd=1, qd=DNSQR(qname=qname.encode())))
        q.time = t
        pkts.append(q)
        t += 0.2
    return pkts


def scen_ics_external():
    """OT PLC (Modbus speaker) -> PUBLIC_C2:443, no periodicity.
    Expect: ICS_EXTERNAL_COMMS / EXTERNAL_IPS_OBSERVED, no beacon."""
    pkts = baseline()
    t = 40.0
    for j, dport in enumerate((443, 8443, 443)):
        syn = (_eth(20, 1) / IP(src=PLC, dst=PUBLIC_C2)
               / TCP(sport=51500 + j, dport=dport, flags="S"))
        syn.time = t
        sa = (_eth(1, 20) / IP(src=PUBLIC_C2, dst=PLC)
              / TCP(sport=dport, dport=51500 + j, flags="SA"))
        sa.time = t + 0.05
        pkts += [syn, sa]
        t += 7.3  # irregular -> no beacon score
    return pkts


def scen_port_scan():
    """SCANNER -> PLC SYN sweep across 240 ports.
    Expect: PORT_SCAN_TARGET / scan-related finding."""
    pkts = baseline()
    t = 30.0
    for port in range(1, 241):
        syn = (_eth(99, 20) / IP(src=SCANNER, dst=PLC)
               / TCP(sport=60000, dport=port, flags="S"))
        syn.time = t
        rst = (_eth(20, 99) / IP(src=PLC, dst=SCANNER)
               / TCP(sport=port, dport=60000, flags="RA"))
        rst.time = t + 0.001
        pkts += [syn, rst]
        t += 0.01
    return pkts


def scen_c2_suspect_channel():
    """OT PLC (Modbus speaker -> Purdue L0-2) -> PUBLIC_C2 on an unknown
    high port (>1024, not OT, not well-known), low volume, irregular.
    Expect: C2_SUSPECT_CHANNEL HIGH (no beacon score)."""
    pkts = baseline()
    t = 45.0
    port = 50505  # deliberately not in OT_PROTOCOLS / WELL_KNOWN_PORTS
    for j, gap in enumerate((0, 11.0, 6.5, 19.0)):
        t += gap
        syn = (_eth(20, 1) / IP(src=PLC, dst=PUBLIC_C2)
               / TCP(sport=52000 + j, dport=port, flags="S"))
        syn.time = t
        pa = (_eth(20, 1) / IP(src=PLC, dst=PUBLIC_C2)
              / TCP(sport=52000 + j, dport=port, flags="PA") / Raw(b"\x11" * 32))
        pa.time = t + 0.04
        pkts += [syn, pa]
    return pkts


def scen_c2_data_exfil():
    """OT PLC -> PUBLIC_C2: strongly asymmetric outbound bulk transfer
    (out_bytes > 10x in_bytes and > 10 KiB).
    Expect: C2_DATA_EXFIL HIGH."""
    pkts = baseline()
    t = 60.0
    syn = _eth(20, 1) / IP(src=PLC, dst=PUBLIC_C2) / TCP(sport=53000, dport=443, flags="S")
    syn.time = t
    sa = _eth(1, 20) / IP(src=PUBLIC_C2, dst=PLC) / TCP(sport=443, dport=53000, flags="SA")
    sa.time = t + 0.02
    pkts += [syn, sa]
    # ~36 KiB outbound across 30 segments; only tiny ACKs return.
    for i in range(30):
        up = (_eth(20, 1) / IP(src=PLC, dst=PUBLIC_C2)
              / TCP(sport=53000, dport=443, flags="PA") / Raw(b"\xab" * 1200))
        up.time = t + 0.1 + i * 0.05
        pkts.append(up)
    ack = _eth(1, 20) / IP(src=PUBLIC_C2, dst=PLC) / TCP(sport=443, dport=53000, flags="A")
    ack.time = t + 2.0
    pkts.append(ack)
    return pkts


def _modbus_write16(tx: int, unit: int, start: int, regs: list[int]) -> bytes:
    """Modbus FC16 — write multiple holding registers."""
    body = struct.pack(">HHB", start, len(regs), len(regs) * 2)
    for v in regs:
        body += struct.pack(">H", v)
    return _modbus(tx, unit, 16, body)


def scen_modbus_write():
    """Three distinct sources issue Modbus write (FC16) to the PLC. The
    write-source detector flags > 2 writers.
    Expect: MODBUS_WRITE_ANON MEDIUM."""
    pkts = baseline()
    t = 25.0
    # (ip, mac_last) writers — HMI is legitimate; ENG + a rogue host are not.
    writers = [(HMI, 50), (ENG, 30), (LAN + "61", 61)]
    for w, (ip, ml) in enumerate(writers):
        for i in range(3):
            rq = (_eth(ml, 20) / IP(src=ip, dst=PLC)
                  / TCP(sport=46000 + w, dport=502, flags="PA")
                  / Raw(_modbus_write16(i, 1, 0, [i + 1, i + 2])))
            rq.time = t
            rp = (_eth(20, ml) / IP(src=PLC, dst=ip)
                  / TCP(sport=502, dport=46000 + w, flags="PA")
                  / Raw(_modbus(i, 1, 16, struct.pack(">HH", 0, 2))))
            rp.time = t + 0.01
            pkts += [rq, rp]
            t += 0.5
    return pkts


def scen_lateral_smb():
    """One host fans out SMB/445 to many internal hosts — the APT plugin's
    lateral-movement signature. Asserted end-to-end via the APT plugin in
    test_detection_plugins.py (no engine risk_finding of its own)."""
    pkts = baseline()
    t = 20.0
    src = LAN + "40"
    for h in range(10, 25):  # 15 distinct SMB targets
        dst = LAN + str(h)
        syn = (_eth(40, h) / IP(src=src, dst=dst) / TCP(sport=47000 + h, dport=445, flags="S"))
        syn.time = t
        sa = (_eth(h, 40) / IP(src=dst, dst=src) / TCP(sport=445, dport=47000 + h, flags="SA"))
        sa.time = t + 0.01
        dat = (_eth(40, h) / IP(src=src, dst=dst) / TCP(sport=47000 + h, dport=445, flags="PA")
               / Raw(b"\xffSMB" + b"\x00" * 28))
        dat.time = t + 0.02
        pkts += [syn, sa, dat]
        t += 0.3
    return pkts


SCENARIOS = {
    "clean": scen_clean,
    "c2_beacon": scen_c2_beacon,
    "dns_exfil": scen_dns_exfil,
    "ics_external": scen_ics_external,
    "port_scan": scen_port_scan,
    "c2_suspect_channel": scen_c2_suspect_channel,
    "c2_data_exfil": scen_c2_data_exfil,
    "modbus_write": scen_modbus_write,
    "lateral_smb": scen_lateral_smb,
}


def generate(outdir: str) -> dict[str, str]:
    os.makedirs(outdir, exist_ok=True)
    written = {}
    for name, fn in SCENARIOS.items():
        pkts = sorted(fn(), key=lambda p: p.time)
        path = os.path.join(outdir, f"{name}.pcap")
        wrpcap(path, pkts)
        written[name] = path
        print(f"  {name:14s} {len(pkts):5d} pkts -> {path}")
    return written


if __name__ == "__main__":
    outdir = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "pcaps"
    )
    print(f"Generating detection-scenario PCAPs into {outdir}")
    generate(outdir)
