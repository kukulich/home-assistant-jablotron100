"""Tests for contrib/hidraw-tcp-proxy --allow access control (stdlib only, no hidraw needed)."""

from __future__ import annotations

import argparse
import importlib.util
import ipaddress
import logging
import os
from pathlib import Path
import socket

import pytest

_PATH = Path(__file__).resolve().parents[1] / "contrib" / "hidraw-tcp-proxy" / "hidraw_tcp_proxy.py"
_spec = importlib.util.spec_from_file_location("hidraw_tcp_proxy", _PATH)
assert _spec is not None and _spec.loader is not None
proxy_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(proxy_mod)


def test_parse_allow_none_means_any():
	assert proxy_mod.parse_allow(None) is None
	assert proxy_mod.parse_allow([]) is None


def test_parse_allow_mixed_and_comma_separated():
	nets = proxy_mod.parse_allow(["10.0.0.6", "10.0.0.10/31, 10.0.0.21", "fd00::/8"])
	assert nets == [
		ipaddress.ip_network("10.0.0.6/32"),
		ipaddress.ip_network("10.0.0.10/31"),
		ipaddress.ip_network("10.0.0.21/32"),
		ipaddress.ip_network("fd00::/8"),
	]


@pytest.mark.parametrize("value", ["10.0.0.300", "evil.example", "10.0.0.0/33", " , "])
def test_parse_allow_rejects_invalid(value):
	with pytest.raises(argparse.ArgumentTypeError):
		proxy_mod.parse_allow([value])


@pytest.mark.parametrize(
	("address", "expected"),
	[
		("10.0.0.6", True),
		("10.0.0.11", True),  # 10.0.0.10/31
		("10.0.0.12", False),
		("10.0.0.5", False),
		("::ffff:10.0.0.6", True),  # IPv4-mapped
		("fd00::1", False),  # no IPv6 network allowed
		("not-an-ip", False),
	],
)
def test_is_allowed(address, expected):
	allow = proxy_mod.parse_allow(["10.0.0.6,10.0.0.10/31"])
	assert proxy_mod.is_allowed(address, allow) is expected


def test_is_allowed_without_list_accepts_everyone():
	assert proxy_mod.is_allowed("192.0.2.1", None) is True


def _proxy_with_listener(allow):
	"""Proxy with a real listener on 127.0.0.1 and a dummy 'device' fd."""
	proxy = proxy_mod.Proxy(None, 0x16D6, 0x0008, "127.0.0.1", 0, allow)
	listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listener.bind(("127.0.0.1", 0))
	listener.listen(8)
	proxy._listener = listener
	read_fd, write_fd = os.pipe()
	proxy._dev_fd = read_fd  # pretend the device is open
	return proxy, listener, (read_fd, write_fd)


def _cleanup(proxy, listener, fds):
	for client in list(proxy._clients.values()):
		client.sock.close()
	listener.close()
	for fd in fds:
		os.close(fd)


def _connect(listener):
	client = socket.create_connection(listener.getsockname(), timeout=2)
	client.settimeout(2)
	return client


def test_allowed_client_is_accepted():
	proxy, listener, fds = _proxy_with_listener(proxy_mod.parse_allow(["127.0.0.1"]))
	try:
		client = _connect(listener)
		proxy._on_accept(0)
		assert len(proxy._clients) == 1
		client.close()
	finally:
		_cleanup(proxy, listener, fds)


def test_disallowed_client_is_closed_and_logged_once(caplog):
	proxy, listener, fds = _proxy_with_listener(proxy_mod.parse_allow(["10.0.0.6"]))
	try:
		with caplog.at_level(logging.WARNING, logger="hidraw-tcp-proxy"):
			for _ in range(3):
				client = _connect(listener)
				proxy._on_accept(0)
				assert client.recv(1) == b""  # closed by the proxy
				client.close()
		assert proxy._clients == {}
		refusals = [r for r in caplog.records if "not in --allow" in r.getMessage()]
		assert len(refusals) == 1  # rate-limited per address
	finally:
		_cleanup(proxy, listener, fds)


def test_no_allow_list_keeps_old_behaviour():
	proxy, listener, fds = _proxy_with_listener(None)
	try:
		client = _connect(listener)
		proxy._on_accept(0)
		assert len(proxy._clients) == 1
		client.close()
	finally:
		_cleanup(proxy, listener, fds)


def test_refused_log_memory_is_bounded(monkeypatch):
	proxy = proxy_mod.Proxy(None, 0x16D6, 0x0008, "127.0.0.1", 0, proxy_mod.parse_allow(["10.0.0.6"]))
	monkeypatch.setattr(proxy_mod, "REFUSED_LOG_MAX_PEERS", 10)
	for i in range(25):
		proxy._log_refused("192.0.2.{}".format(i), "192.0.2.{}:1".format(i))
	assert len(proxy._refused_logged) <= 10


# --- forwarding, framing and device loss (fake hidraw = SOCK_SEQPACKET pair) ---

import struct  # noqa: E402
import sys  # noqa: E402
import time  # noqa: E402

_FRAME = struct.Struct("!H")


def _frame(payload: bytes) -> bytes:
	return _FRAME.pack(len(payload)) + payload


@pytest.fixture
def running_proxy():
	"""Proxy with a listener registered in its selector and a fake hidraw device.

	The device is one end of a SOCK_SEQPACKET socketpair, which keeps report
	boundaries like hidraw does; the test holds the other end.
	"""
	if sys.platform != "linux":
		pytest.skip("Uses SOCK_SEQPACKET socketpair")
	proxy = proxy_mod.Proxy(None, 0x16D6, 0x0008, "127.0.0.1", 0, None)
	listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	listener.bind(("127.0.0.1", 0))
	listener.listen(8)
	listener.setblocking(False)
	proxy._listener = listener
	proxy._sel.register(listener, proxy_mod.selectors.EVENT_READ, proxy._on_accept)
	dev_proxy_side, dev_test_side = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
	dev_test_side.settimeout(2)
	proxy._dev_fd = dev_proxy_side.detach()  # the proxy owns and closes the fd
	proxy._dev_path = "fake-hidraw"
	proxy._sel.register(proxy._dev_fd, proxy_mod.selectors.EVENT_READ, proxy._on_device_readable)
	try:
		yield proxy, listener, dev_test_side
	finally:
		for client in list(proxy._clients.values()):
			client.sock.close()
		listener.close()
		dev_test_side.close()
		if proxy._dev_fd is not None:
			os.close(proxy._dev_fd)


def _pump(proxy, until, timeout=2.0):
	deadline = time.monotonic() + timeout
	while time.monotonic() < deadline:
		for key, mask in proxy._sel.select(timeout=0.05):
			key.data(mask)
		if until():
			return
	raise AssertionError("condition not reached")


def _connect_client(proxy, listener):
	before = len(proxy._clients)
	client = socket.create_connection(listener.getsockname(), timeout=2)
	_pump(proxy, lambda: len(proxy._clients) == before + 1)
	return client


def _recv_exact(sock, size):
	data = b""
	while len(data) < size:
		chunk = sock.recv(size - len(data))
		assert chunk, "connection closed"
		data += chunk
	return data


def test_device_report_is_broadcast_to_all_clients(running_proxy):
	proxy, listener, device = running_proxy
	first = _connect_client(proxy, listener)
	second = _connect_client(proxy, listener)
	try:
		report = bytes(range(64))
		device.send(report)
		_pump(proxy, lambda: True, timeout=0.2)
		for client in (first, second):
			assert _recv_exact(client, 66) == _frame(report)
	finally:
		first.close()
		second.close()


def test_fragmented_client_frame_is_written_as_one_report(running_proxy):
	proxy, listener, device = running_proxy
	client = _connect_client(proxy, listener)
	try:
		data = _frame(b"\x80\x01\x02\x03")
		for i in range(len(data)):
			client.sendall(data[i:i + 1])
			_pump(proxy, lambda: True, timeout=0.02)
		assert device.recv(4096) == b"\x80\x01\x02\x03"
	finally:
		client.close()


def test_coalesced_client_frames_are_written_as_separate_reports(running_proxy):
	proxy, listener, device = running_proxy
	client = _connect_client(proxy, listener)
	try:
		client.sendall(_frame(b"\x01") + _frame(b"\x02\x02") + _frame(b"\x03\x03\x03"))
		received = []
		def got_all():
			try:
				device.setblocking(False)
				while True:
					received.append(device.recv(4096))
			except BlockingIOError:
				return len(received) == 3
		_pump(proxy, got_all)
		assert received == [b"\x01", b"\x02\x02", b"\x03\x03\x03"]
	finally:
		client.close()


def test_oversized_frame_drops_client(running_proxy):
	proxy, listener, _ = running_proxy
	client = _connect_client(proxy, listener)
	try:
		client.sendall(_FRAME.pack(proxy_mod.MAX_FRAME + 1))
		_pump(proxy, lambda: not proxy._clients)
		assert client.recv(1) == b""
	finally:
		client.close()


def test_device_loss_disconnects_clients_and_refuses_new_ones(running_proxy):
	proxy, listener, device = running_proxy
	client = _connect_client(proxy, listener)
	try:
		device.close()  # cable unplugged: the device read returns EOF
		_pump(proxy, lambda: proxy._dev_fd is None)
		assert proxy._clients == {}
		assert client.recv(1) == b""

		# Until the device is back, new clients are closed right away
		proxy._next_open_attempt = time.monotonic() + 60
		late = socket.create_connection(listener.getsockname(), timeout=2)
		try:
			_pump(proxy, lambda: True, timeout=0.2)
			assert late.recv(1) == b""
			assert proxy._clients == {}
		finally:
			late.close()
	finally:
		client.close()


def test_client_disconnect_keeps_device_and_other_clients(running_proxy):
	proxy, listener, device = running_proxy
	leaving = _connect_client(proxy, listener)
	staying = _connect_client(proxy, listener)
	try:
		leaving.close()
		_pump(proxy, lambda: len(proxy._clients) == 1)
		assert proxy._dev_fd is not None
		device.send(b"\x55")
		_pump(proxy, lambda: True, timeout=0.2)
		assert _recv_exact(staying, 3) == _frame(b"\x55")
	finally:
		staying.close()
