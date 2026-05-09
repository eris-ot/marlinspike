"""capd command-line entry points.

Three subcommands:
  list-interfaces  — quick visibility into what capd will offer the workbench
  validate-bpf     — compile a filter without touching an interface
  serve            — run the daemon
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__, bpf, interfaces
from .server import CapdServer, ServerConfig


def _cmd_list_interfaces(args: argparse.Namespace) -> int:
    ifaces = interfaces.list_interfaces(include_virtual=args.all)
    if args.json:
        print(json.dumps(ifaces, indent=2))
    else:
        print(interfaces.format_table(ifaces))
    return 0


def _cmd_validate_bpf(args: argparse.Namespace) -> int:
    res = bpf.validate(args.filter, link_type=args.link_type)
    if args.json:
        print(json.dumps({"ok": res.ok, "error": res.error}))
        return 0 if res.ok else 1
    if res.ok:
        print("ok")
        return 0
    print(f"invalid: {res.error}", file=sys.stderr)
    return 1


def _cmd_serve(args: argparse.Namespace) -> int:
    sock_path = Path(args.socket)
    sock_path.parent.mkdir(parents=True, exist_ok=True)

    capture_root = Path(args.capture_root)
    capture_root.mkdir(parents=True, exist_ok=True)

    allowed_uids: set[int] = set()
    if args.allow_uid:
        allowed_uids.update(int(u) for u in args.allow_uid)
    # Always allow the user running capd itself.
    allowed_uids.add(os.geteuid())

    cfg = ServerConfig(
        socket_path=sock_path,
        capture_root=capture_root,
        allowed_uids=allowed_uids,
    )
    srv = CapdServer(cfg)
    try:
        asyncio.run(srv.serve())
    except KeyboardInterrupt:
        return 0
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="capd", description="MarlinSpike capture daemon.")
    parser.add_argument("--version", action="version", version=f"capd {__version__}")
    parser.add_argument("-v", "--verbose", action="count", default=0)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list-interfaces", help="Enumerate visible interfaces.")
    p_list.add_argument("--all", action="store_true", help="Include virtual / loopback interfaces.")
    p_list.add_argument("--json", action="store_true", help="Emit JSON instead of a table.")
    p_list.set_defaults(func=_cmd_list_interfaces)

    p_bpf = sub.add_parser("validate-bpf", help="Validate a BPF filter without opening an interface.")
    p_bpf.add_argument("filter", help="BPF filter expression, e.g. 'tcp port 502'.")
    p_bpf.add_argument("--link-type", type=int, default=bpf.DLT_EN10MB,
                       help=f"DLT (default {bpf.DLT_EN10MB} = EN10MB Ethernet).")
    p_bpf.add_argument("--json", action="store_true")
    p_bpf.set_defaults(func=_cmd_validate_bpf)

    p_srv = sub.add_parser("serve", help="Run the capd uds JSON-RPC server.")
    p_srv.add_argument("--socket", default="/var/run/marlinspike-capd.sock",
                       help="Unix-domain socket path.")
    p_srv.add_argument("--capture-root", default="/var/lib/marlinspike/captures",
                       help="Root directory for per-session capture files.")
    p_srv.add_argument("--allow-uid", action="append",
                       help="Permit this uid to talk to the socket. May be given multiple times. "
                            "The euid running capd is always allowed.")
    p_srv.set_defaults(func=_cmd_serve)

    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.WARNING - 10 * min(args.verbose, 2),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
