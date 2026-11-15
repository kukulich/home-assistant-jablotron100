"""Tests for the optional ``tcp://`` serial port transport (hidraw-tcp-proxy client side)."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import socket
import struct
import threading
import time
from unittest.mock import Mock

import pytest

from custom_components.jablotron100.jablotron import Jablotron
from custom_components.jablotron100.stream import (
	TCP_DEFAULT_PORT,
	JablotronReadStream,
	JablotronTcpWriteStream,
	is_tcp_serial_port,
	open_serial_port,
	parse_tcp_serial_port,
)

FRAME = struct.Struct("!H")


def frame(payload: bytes) -> bytes:
	return FRAME.pack(len(payload)) + payload


class FakeProxy:
	"""Minimal TCP server standing in for hidraw-tcp-proxy."""

	def __init__(self) -> None:
		self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self.listener.bind(("127.0.0.1", 0))
		self.listener.listen(8)
		self.listener.settimeout(5)
		self.port = self.listener.getsockname()[1]
		self.url = "tcp://127.0.0.1:{}".format(self.port)

	def accept(self) -> socket.socket:
		conn, _ = self.listener.accept()
		conn.settimeout(5)
		return conn

	def close(self) -> None:
		self.listener.close()


@pytest.fixture
def proxy():
	server = FakeProxy()
	try:
		yield server
	finally:
		server.close()


# --- URL parsing ---------------------------------------------------------


@pytest.mark.parametrize(
	("serial_port", "expected"),
	[
		("tcp://10.0.0.8:8765", ("10.0.0.8", 8765)),
		("tcp://10.0.0.8", ("10.0.0.8", TCP_DEFAULT_PORT)),
		("tcp://10.0.0.8:9000/", ("10.0.0.8", 9000)),
		("tcp://jablotron.local:8765", ("jablotron.local", 8765)),
		("tcp://[fd00::8]:8765", ("fd00::8", 8765)),
		("tcp://[fd00::8]", ("fd00::8", TCP_DEFAULT_PORT)),
		("tcp://fd00::8", ("fd00::8", TCP_DEFAULT_PORT)),
	],
)
def test_parse_tcp_serial_port(serial_port, expected):
	assert is_tcp_serial_port(serial_port)
	assert parse_tcp_serial_port(serial_port) == expected


@pytest.mark.parametrize(
	"serial_port",
	["tcp://", "tcp://:8765", "tcp://host:port", "tcp://host:0", "tcp://host:65536", "tcp://[fd00::8", "tcp://[fd00::8]x"],
)
def test_parse_tcp_serial_port_rejects_invalid(serial_port):
	with pytest.raises(ValueError):
		parse_tcp_serial_port(serial_port)


@pytest.mark.parametrize("serial_port", ["/dev/hidraw0", "auto", "/dev/tcp://x"])
def test_local_paths_are_not_tcp(serial_port):
	assert not is_tcp_serial_port(serial_port)


def test_tcp_serial_port_is_accepted_as_jablotron_port():
	assert Jablotron._is_jablotron_serial_port("tcp://10.0.0.8:8765")


# --- read stream -----------------------------------------------------------


def test_read_reassembles_fragmented_frames(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		packet = bytes(range(64))
		data = frame(packet)

		def send_byte_by_byte():
			for i in range(len(data)):
				conn.sendall(data[i:i + 1])
				time.sleep(0.001)

		sender = threading.Thread(target=send_byte_by_byte)
		sender.start()
		assert stream.read(64) == packet
		sender.join()
	finally:
		stream.close()
		conn.close()


def test_read_splits_coalesced_frames(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		packets = [b"\x51\x02\x00\x01", bytes(64), b"\x40"]
		# all frames in one TCP segment, the last one split across two sends
		blob = b"".join(frame(p) for p in packets)
		conn.sendall(blob[:-1])
		assert stream.read(64) == packets[0]
		assert stream.read(64) == packets[1]
		conn.sendall(blob[-1:])
		assert stream.read(64) == packets[2]
	finally:
		stream.close()
		conn.close()


def test_read_skips_empty_frames(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		# b"" from read() means "connection closed", so an empty frame must not
		# be returned as a packet
		conn.sendall(frame(b"") + frame(b"\x01"))
		assert stream.read(64) == b"\x01"
	finally:
		stream.close()
		conn.close()


def test_read_returns_eof_when_proxy_closes(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		conn.sendall(frame(b"\x01\x02"))
		conn.close()
		assert stream.read(64) == b"\x01\x02"
		assert stream.read(64) == b""
	finally:
		stream.close()


def test_read_returns_eof_on_connection_reset(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		# RST instead of FIN
		conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
		conn.close()
		assert stream.read(64) == b""
	finally:
		stream.close()


def test_read_drops_incomplete_frame_on_eof(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		conn.sendall(frame(b"\x01\x02\x03")[:-1])
		conn.close()
		assert stream.read(64) == b""
	finally:
		stream.close()


def test_read_returns_none_when_stopped(proxy):
	stop = threading.Event()
	stream = JablotronReadStream(proxy.url, stop)
	conn = proxy.accept()
	try:
		threading.Timer(0.1, stop.set).start()
		started = time.monotonic()
		assert stream.read(64) is None
		assert time.monotonic() - started < 2
	finally:
		stream.close()
		conn.close()


def test_open_fails_when_proxy_unreachable():
	sock = socket.socket()
	sock.bind(("127.0.0.1", 0))
	port = sock.getsockname()[1]
	sock.close()  # nothing listens on the port now
	with pytest.raises(OSError):
		JablotronReadStream("tcp://127.0.0.1:{}".format(port), threading.Event())


def test_close_closes_connection(proxy):
	stream = JablotronReadStream(proxy.url, threading.Event())
	conn = proxy.accept()
	try:
		stream.close()
		assert conn.recv(1) == b""
		stream.close()  # idempotent
	finally:
		conn.close()


# --- write stream ----------------------------------------------------------


def test_write_sends_one_frame_per_packet(proxy):
	stream = open_serial_port(proxy.url, "wb")
	assert isinstance(stream, JablotronTcpWriteStream)
	conn = proxy.accept()
	try:
		with stream:
			assert stream.write(b"\x80\x01\x02") == 3
			assert stream.write(bytes(64)) == 64
		data = b""
		while True:
			chunk = conn.recv(4096)
			if not chunk:
				break
			data += chunk
		assert data == frame(b"\x80\x01\x02") + frame(bytes(64))
	finally:
		conn.close()


def test_open_serial_port_refuses_tcp_read_mode():
	with pytest.raises(ValueError):
		open_serial_port("tcp://127.0.0.1:1", "rb")


# --- integration reader loop ---------------------------------------------


def _reader_jablotron(serial_port: str) -> Jablotron:
	jablotron = object.__new__(Jablotron)
	jablotron._serial_port = serial_port
	jablotron._config = {"serial_port": serial_port}
	jablotron._stream_stop_event = threading.Event()
	jablotron._stream_data_updating_event = threading.Event()
	jablotron._stream_diagnostics_event = threading.Event()
	jablotron._login_failed = threading.Event()
	jablotron.last_update_success = False
	jablotron.get_packets_from_packet = Mock(return_value=[])
	jablotron._log_incoming_packet = Mock()
	jablotron._redetect_serial_port = Mock()

	available = threading.Event()
	unavailable = threading.Event()

	def set_available():
		jablotron.last_update_success = True
		unavailable.clear()
		available.set()

	def set_unavailable():
		jablotron.last_update_success = False
		available.clear()
		unavailable.set()

	jablotron._set_available = Mock(side_effect=set_available)
	jablotron._set_unavailable = Mock(side_effect=set_unavailable)
	jablotron.available_event = available  # type: ignore[attr-defined]
	jablotron.unavailable_event = unavailable  # type: ignore[attr-defined]
	return jablotron


def test_reader_marks_unavailable_on_disconnect_and_recovers(proxy):
	jablotron = _reader_jablotron(proxy.url)
	executor = ThreadPoolExecutor(max_workers=1)
	jablotron._stream_thread_pool_executor = executor
	reader = executor.submit(jablotron._read_packets)
	try:
		conn = proxy.accept()
		conn.sendall(frame(b"\x51\x01"))
		assert jablotron.available_event.wait(5)

		# Proxy restarts / cable unplugged: connection closed
		conn.close()
		assert jablotron.unavailable_event.wait(5)
		assert jablotron._login_failed.is_set()

		# Integration reconnects on its own and becomes available again
		conn = proxy.accept()
		conn.sendall(frame(b"\x51\x01"))
		assert jablotron.available_event.wait(5)
		assert jablotron._set_unavailable.call_count == 1
		conn.close()
	finally:
		jablotron.shutdown()
		reader.result(timeout=5)
		executor.shutdown(wait=True, cancel_futures=True)


def test_reader_keeps_retrying_while_proxy_is_unreachable():
	listener = socket.socket()
	listener.bind(("127.0.0.1", 0))
	port = listener.getsockname()[1]
	listener.close()  # nothing listens yet
	url = "tcp://127.0.0.1:{}".format(port)

	jablotron = _reader_jablotron(url)
	executor = ThreadPoolExecutor(max_workers=1)
	jablotron._stream_thread_pool_executor = executor
	reader = executor.submit(jablotron._read_packets)
	server = None
	try:
		assert jablotron.unavailable_event.wait(5)

		server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		server.bind(("127.0.0.1", port))
		server.listen(1)
		server.settimeout(10)
		conn, _ = server.accept()
		conn.sendall(frame(b"\x51\x01"))
		assert jablotron.available_event.wait(5)
		conn.close()
	finally:
		jablotron.shutdown()
		reader.result(timeout=5)
		executor.shutdown(wait=True, cancel_futures=True)
		if server is not None:
			server.close()


def test_shutdown_stops_idle_tcp_reader_and_closes_connection(proxy):
	jablotron = _reader_jablotron(proxy.url)
	executor = ThreadPoolExecutor(max_workers=1)
	jablotron._stream_thread_pool_executor = executor
	reader = executor.submit(jablotron._read_packets)
	try:
		conn = proxy.accept()
		time.sleep(0.3)  # reader idles in select()
		started = time.monotonic()
		jablotron.shutdown()
		reader.result(timeout=2)
		assert time.monotonic() - started < 2
		assert conn.recv(1) == b""  # connection closed by the integration
		jablotron._set_unavailable.assert_not_called()
		conn.close()
	finally:
		jablotron._stream_stop_event.set()
		executor.shutdown(wait=True, cancel_futures=True)
