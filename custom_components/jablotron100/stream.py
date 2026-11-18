import errno
import os
import select
import socket
import stat
import struct
import threading
from typing import BinaryIO, Literal

TCP_PREFIX = "tcp://"
TCP_DEFAULT_PORT = 8765
TCP_CONNECT_TIMEOUT = 5.0
TCP_FRAME_HEADER = struct.Struct("!H")


def is_tcp_serial_port(serial_port: str) -> bool:
	return serial_port.startswith(TCP_PREFIX)


def parse_tcp_serial_port(serial_port: str) -> tuple[str, int]:
	"""``tcp://host[:port]`` -> (host, port); IPv6 hosts as ``tcp://[::1]:8765``."""
	address = serial_port[len(TCP_PREFIX):].strip("/")
	if address.startswith("["):
		host, sep, rest = address[1:].partition("]")
		if not sep or not host or (rest and not rest.startswith(":")):
			raise ValueError("Invalid TCP serial port: {}".format(serial_port))
		port = rest[1:]
	elif address.count(":") == 1:
		host, port = address.split(":")
	else:
		host, port = address, ""
	if not host:
		raise ValueError("Invalid TCP serial port: {}".format(serial_port))
	if not port:
		return host, TCP_DEFAULT_PORT
	if not port.isdigit() or not 0 < int(port) < 65536:
		raise ValueError("Invalid TCP serial port: {}".format(serial_port))
	return host, int(port)


def _tcp_connect(serial_port: str) -> socket.socket:
	host, port = parse_tcp_serial_port(serial_port)
	sock = socket.create_connection((host, port), timeout=TCP_CONNECT_TIMEOUT)
	sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
	return sock


class JablotronTcpWriteStream:
	"""Write-only stream over hidraw-tcp-proxy; one connection per instance."""

	def __init__(self, serial_port: str) -> None:
		self._sock = _tcp_connect(serial_port)

	def write(self, packet: bytes) -> int:
		self._sock.sendall(TCP_FRAME_HEADER.pack(len(packet)) + packet)
		return len(packet)

	def close(self) -> None:
		try:
			self._sock.close()
		except OSError:
			pass

	def __enter__(self) -> "JablotronTcpWriteStream":
		return self

	def __exit__(self, *_: object) -> None:
		self.close()


def open_serial_port(serial_port: str, mode: Literal["rb", "wb"]) -> BinaryIO:
	if is_tcp_serial_port(serial_port):
		if mode != "wb":
			raise ValueError("Use JablotronReadStream for reading from a TCP serial port")
		return JablotronTcpWriteStream(serial_port)  # type: ignore[return-value]

	flags = os.O_RDONLY if mode == "rb" else os.O_WRONLY
	fd = os.open(serial_port, flags | getattr(os, "O_NOCTTY", 0))
	try:
		if not stat.S_ISCHR(os.fstat(fd).st_mode):
			raise OSError(
				errno.ENODEV,
				"Serial port is not a character device; check for a stale regular file before reconnecting USB",
				serial_port,
			)
		return os.fdopen(fd, mode, buffering=0)
	except BaseException:
		os.close(fd)
		raise


class JablotronReadStream:
	"""Read stream: hidraw device or hidraw-tcp-proxy.

	``read()`` returns one packet, ``b""`` when the stream was closed by the
	other side, ``None`` when a stop event was set.
	"""

	def __init__(self, serial_port: str, *stop_events: threading.Event) -> None:
		self._stop_events = stop_events
		self._sock: socket.socket | None = None
		self._stream: BinaryIO | None = None
		self._buffer = b""

		if is_tcp_serial_port(serial_port):
			self._sock = _tcp_connect(serial_port)
			self._sock.setblocking(False)
			return

		self._stream = open_serial_port(serial_port, "rb")
		try:
			os.set_blocking(self._stream.fileno(), False)
		except BaseException:
			self._stream.close()
			raise

	def _stopped(self) -> bool:
		return any(event.is_set() for event in self._stop_events)

	def read(self, size: int) -> bytes | None:
		if self._sock is not None:
			return self._read_tcp()

		assert self._stream is not None
		while not self._stopped():
			readable, _, _ = select.select([self._stream], [], [], 0.2)
			if self._stopped():
				break
			if readable:
				packet = self._stream.read(size)
				if packet is not None:
					return packet
		return None

	def _read_tcp(self) -> bytes | None:
		assert self._sock is not None
		while not self._stopped():
			frame = self._pop_frame()
			if frame:
				return frame
			if frame is not None:
				# Empty frame: skip it, b"" is reserved for "connection closed"
				continue

			readable, _, _ = select.select([self._sock], [], [], 0.2)
			if self._stopped():
				break
			if not readable:
				continue

			try:
				data = self._sock.recv(4096)
			except BlockingIOError:
				continue
			except OSError:
				# Connection reset, host unreachable, ...: behave like a closed
				# hidraw stream so the caller marks entities unavailable and reconnects
				return b""
			if not data:
				return b""
			self._buffer += data
		return None

	def _pop_frame(self) -> bytes | None:
		if len(self._buffer) < TCP_FRAME_HEADER.size:
			return None
		(length,) = TCP_FRAME_HEADER.unpack_from(self._buffer)
		end = TCP_FRAME_HEADER.size + length
		if len(self._buffer) < end:
			return None
		frame = self._buffer[TCP_FRAME_HEADER.size:end]
		self._buffer = self._buffer[end:]
		return frame

	def close(self) -> None:
		if self._sock is not None:
			try:
				self._sock.close()
			except OSError:
				pass
			return
		assert self._stream is not None
		self._stream.close()
