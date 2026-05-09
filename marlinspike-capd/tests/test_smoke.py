"""Smoke tests — exercise the no-root parts of capd."""

from __future__ import annotations

import pytest

from capd import bpf, interfaces


def test_list_interfaces_returns_at_least_one():
    ifaces = interfaces.list_interfaces(include_virtual=True)
    assert isinstance(ifaces, list)
    assert ifaces, "every host has at least loopback"
    assert all("name" in i for i in ifaces)


def test_list_interfaces_default_hides_virtual_but_keeps_any():
    ifaces = interfaces.list_interfaces(include_virtual=False)
    names = {i["name"] for i in ifaces}
    assert "any" in names, "default view should expose the 'any' pseudo-device"
    assert "lo" not in names, "default view should hide loopback"


def test_format_table_handles_empty():
    assert interfaces.format_table([]) == "(no interfaces)"


def test_bpf_empty_filter_is_valid():
    res = bpf.validate("")
    assert res.ok
    assert res.error is None


def test_bpf_simple_filter_compiles():
    res = bpf.validate("tcp port 502")
    if not res.ok and res.error and "libpcap unavailable" in res.error:
        pytest.skip("libpcap not available on this host")
    assert res.ok, res.error


def test_bpf_garbage_filter_rejected():
    res = bpf.validate("this is not a real filter expression !!!")
    if not res.ok and res.error and "libpcap unavailable" in res.error:
        pytest.skip("libpcap not available on this host")
    assert not res.ok
    assert res.error
