#!/usr/bin/env python3
"""Expose a Jablotron JA-100 USB (hidraw) device over TCP.

Protocol (both directions): frames of ``!H`` big-endian length + payload.

* Every HID input report read from the device is broadcast to all connected
  clients as one frame (this mirrors hidraw semantics, where every open
  reader gets its own copy of every report).
* Every frame received from a client is written to the device as one
  ``write()`` (one HID output report).

Single-threaded ``selectors`` loop, stdlib only.  When the device disappears
(USB re-plug) all clients are disconnected, so they see EOF exactly as on a
vanished hidraw device; new connections are refused until the device is
re-opened (retried every 2 s).

The traffic is NOT encrypted or authenticated: anyone who can reach the port
can read the alarm state and send commands to the control panel.

Access control: ``--allow`` limits which client addresses may connect
(IPv4/IPv6 addresses or CIDR networks, repeatable or comma-separated).  Other
clients are closed right after ``accept()`` and logged (rate-limited per
address).  Without ``--allow`` every client is accepted, as before; the proxy
logs a warning at startup.  This is a second layer -- keep a host firewall too.
"""

import argparse
import errno
import ipaddress
import logging
import os
import selectors
import socket
import stat
import struct
import sys
import time

LOGGER = logging.getLogger("hidraw-tcp-proxy")

FRAME_HEADER = struct.Struct("!H")
REPORT_SIZE = 64
HIDRAW_SYSFS = "/sys/class/hidraw"
MAX_FRAME = 4096
REFUSED_LOG_INTERVAL = 60.0
REFUSED_LOG_MAX_PEERS = 1024

Network = ipaddress.IPv4Network | ipaddress.IPv6Network


def parse_allow(values: list[str] | None) -> list[Network] | None:
	"""``["10.0.0.6", "10.0.0.10/31,10.0.0.21"]`` -> networks; None = allow all."""
	if not values:
		return None
	networks: list[Network] = []
	for value in values:
		for item in value.split(","):
			item = item.strip()
			if not item:
				continue
			try:
				networks.append(ipaddress.ip_network(item, strict=False))
			except ValueError as ex:
				raise argparse.ArgumentTypeError("invalid --allow entry {!r}: {}".format(item, ex)) from ex
	if not networks:
		raise argparse.ArgumentTypeError("--allow given but empty")
	return networks


def is_allowed(address: str, allow: list[Network] | None) -> bool:
	if allow is None:
		return True
	try:
		ip = ipaddress.ip_address(address)
	except ValueError:
		return False
	if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
		ip = ip.ipv4_mapped
	return any(ip in net for net in allow if net.version == ip.version)


def find_hidraw_device(vid: int, pid: int) -> str | None:
	wanted = "{:08X}:{:08X}".format(vid, pid)
	try:
		names = sorted(os.listdir(HIDRAW_SYSFS))
	except OSError:
		return None
	for name in names:
		try:
			with open(os.path.join(HIDRAW_SYSFS, name, "device", "uevent")) as fh:
				for line in fh:
					if line.startswith("HID_ID=") and line.strip().endswith(wanted):
						return "/dev/" + name
		except OSError:
			continue
	return None


class Client:
	def __init__(self, sock: socket.socket, peer: str) -> None:
		self.sock = sock
		self.peer = peer
		self.buffer = b""


class Proxy:
	def __init__(
		self,
		device: str | None,
		vid: int,
		pid: int,
		bind: str,
		port: int,
		allow: list[Network] | None = None,
	) -> None:
		self._device_arg = device
		self._vid = vid
		self._pid = pid
		self._bind = bind
		self._port = port
		self._sel = selectors.DefaultSelector()
		self._clients: dict[int, Client] = {}
		self._dev_fd: int | None = None
		self._dev_path: str | None = None
		self._next_open_attempt = 0.0
		self._allow = allow
		self._refused_logged: dict[str, float] = {}

	# --- device -----------------------------------------------------------

	def _open_device(self) -> None:
		now = time.monotonic()
		if now < self._next_open_attempt:
			return
		self._next_open_attempt = now + 2.0

		path = self._device_arg or find_hidraw_device(self._vid, self._pid)
		if path is None:
			return
		try:
			fd = os.open(path, os.O_RDWR | os.O_NONBLOCK | os.O_NOCTTY)
			if not stat.S_ISCHR(os.fstat(fd).st_mode):
				os.close(fd)
				LOGGER.error("%s is not a character device", path)
				return
		except OSError as ex:
			LOGGER.warning("Cannot open %s: %s", path, ex)
			return

		self._dev_fd = fd
		self._dev_path = path
		self._sel.register(fd, selectors.EVENT_READ, self._on_device_readable)
		LOGGER.info("Device opened: %s", path)

	def _close_device(self, reason: str) -> None:
		if self._dev_fd is None:
			return
		LOGGER.warning("Device %s closed: %s", self._dev_path, reason)
		try:
			self._sel.unregister(self._dev_fd)
		except (KeyError, ValueError):
			pass
		try:
			os.close(self._dev_fd)
		except OSError:
			pass
		self._dev_fd = None
		self._dev_path = None
		# Disconnect everyone so clients see EOF, exactly as they would on a
		# vanished hidraw device, and mark their entities unavailable.
		for client in list(self._clients.values()):
			self._drop_client(client, "device lost")

	def _on_device_readable(self, _mask: int) -> None:
		assert self._dev_fd is not None
		try:
			report = os.read(self._dev_fd, REPORT_SIZE)
		except BlockingIOError:
			return
		except OSError as ex:
			self._close_device(str(ex))
			return
		if not report:
			self._close_device("EOF")
			return
		frame = FRAME_HEADER.pack(len(report)) + report
		for client in list(self._clients.values()):
			try:
				client.sock.sendall(frame)
			except OSError as ex:
				self._drop_client(client, str(ex))

	def _write_device(self, payload: bytes, client: Client) -> None:
		if self._dev_fd is None:
			LOGGER.warning("Dropping %d bytes from %s: device not open", len(payload), client.peer)
			return
		try:
			os.write(self._dev_fd, payload)
		except OSError as ex:
			if ex.errno == errno.EAGAIN:
				LOGGER.warning("Device busy, dropped %d bytes from %s", len(payload), client.peer)
				return
			self._close_device(str(ex))

	# --- clients ----------------------------------------------------------

	def _on_accept(self, _mask: int) -> None:
		try:
			sock, addr = self._listener.accept()
		except OSError:
			return
		peer = "{}:{}".format(*addr[:2])
		if not is_allowed(addr[0], self._allow):
			self._log_refused(addr[0], peer)
			sock.close()
			return
		if self._dev_fd is None:
			# No device: refuse so the client fails fast instead of waiting on
			# a silent connection.
			LOGGER.warning("Refusing %s: device not open", peer)
			sock.close()
			return
		sock.setblocking(False)
		sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		client = Client(sock, peer)
		self._clients[sock.fileno()] = client
		self._sel.register(sock, selectors.EVENT_READ, lambda m, c=client: self._on_client_readable(c))
		LOGGER.debug("Client connected: %s (%d total)", peer, len(self._clients))

	def _log_refused(self, address: str, peer: str) -> None:
		now = time.monotonic()
		last = self._refused_logged.get(address)
		if last is not None and now - last < REFUSED_LOG_INTERVAL:
			return
		if len(self._refused_logged) >= REFUSED_LOG_MAX_PEERS:
			self._refused_logged.clear()
		self._refused_logged[address] = now
		LOGGER.warning("Refusing %s: not in --allow (further refusals from this address muted for %ds)", peer, REFUSED_LOG_INTERVAL)

	def _drop_client(self, client: Client, reason: str) -> None:
		fd = client.sock.fileno()
		if fd in self._clients:
			del self._clients[fd]
		try:
			self._sel.unregister(client.sock)
		except (KeyError, ValueError):
			pass
		try:
			client.sock.close()
		except OSError:
			pass
		level = logging.INFO if reason == "device lost" else logging.DEBUG
		LOGGER.log(level, "Client disconnected: %s (%s, %d left)", client.peer, reason, len(self._clients))

	def _on_client_readable(self, client: Client) -> None:
		try:
			data = client.sock.recv(4096)
		except BlockingIOError:
			return
		except OSError as ex:
			self._drop_client(client, str(ex))
			return
		if not data:
			self._drop_client(client, "EOF")
			return
		client.buffer += data
		while len(client.buffer) >= FRAME_HEADER.size:
			(length,) = FRAME_HEADER.unpack_from(client.buffer)
			if length > MAX_FRAME:
				self._drop_client(client, "frame too large ({})".format(length))
				return
			if len(client.buffer) < FRAME_HEADER.size + length:
				break
			payload = client.buffer[FRAME_HEADER.size:FRAME_HEADER.size + length]
			client.buffer = client.buffer[FRAME_HEADER.size + length:]
			self._write_device(payload, client)

	# --- main loop --------------------------------------------------------

	def run(self) -> None:
		self._listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self._listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
		self._listener.bind((self._bind, self._port))
		self._listener.listen(8)
		self._listener.setblocking(False)
		self._sel.register(self._listener, selectors.EVENT_READ, self._on_accept)
		LOGGER.info("Listening on %s:%d", self._bind, self._port)
		if self._allow is None:
			LOGGER.warning("No --allow given: accepting clients from any address")
		else:
			LOGGER.info("Allowed clients: %s", ", ".join(str(n) for n in self._allow))

		while True:
			if self._dev_fd is None:
				self._open_device()
			for key, mask in self._sel.select(timeout=1.0):
				key.data(mask)


def main() -> int:
	parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
	parser.add_argument("--device", help="hidraw device path (default: autodetect by VID/PID)")
	parser.add_argument("--vid", default="16d6", help="USB vendor id, hex (default: 16d6)")
	parser.add_argument("--pid", default="0008", help="USB product id, hex (default: 0008)")
	parser.add_argument("--bind", default="0.0.0.0")
	parser.add_argument("--port", type=int, default=8765)
	parser.add_argument(
		"--allow",
		action="append",
		metavar="IP[/PREFIX][,...]",
		help="allowed client address or network; repeatable or comma-separated (default: any)",
	)
	parser.add_argument("--debug", action="store_true")
	args = parser.parse_args()
	try:
		allow = parse_allow(args.allow)
	except argparse.ArgumentTypeError as ex:
		parser.error(str(ex))

	logging.basicConfig(
		level=logging.DEBUG if args.debug else logging.INFO,
		format="%(asctime)s %(levelname)s %(message)s",
		stream=sys.stdout,
	)
	Proxy(args.device, int(args.vid, 16), int(args.pid, 16), args.bind, args.port, allow).run()
	return 0


if __name__ == "__main__":
	sys.exit(main())
