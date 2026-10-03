import errno
import os
import select
import stat
import threading
from typing import BinaryIO, Literal


def open_serial_port(serial_port: str, mode: Literal["rb", "wb"]) -> BinaryIO:
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
	def __init__(self, serial_port: str, *stop_events: threading.Event) -> None:
		self._stop_events = stop_events
		self._stream = open_serial_port(serial_port, "rb")
		try:
			os.set_blocking(self._stream.fileno(), False)
		except BaseException:
			self._stream.close()
			raise

	def read(self, size: int) -> bytes | None:
		while not any(event.is_set() for event in self._stop_events):
			readable, _, _ = select.select([self._stream], [], [], 0.2)
			if any(event.is_set() for event in self._stop_events):
				break
			if readable:
				packet = self._stream.read(size)
				if packet is not None:
					return packet
		return None

	def close(self) -> None:
		self._stream.close()