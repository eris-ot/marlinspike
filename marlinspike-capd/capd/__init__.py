"""MarlinSpike capture daemon (capd).

Privileged sidecar that owns CAP_NET_RAW / CAP_NET_ADMIN. The unprivileged
MarlinSpike web app talks to capd over a unix-domain socket; capd
enumerates interfaces, validates BPF filters, and supervises dumpcap with
ring-buffer rotation.
"""

__version__ = "0.1.0"
