import os
import select
import threading


class JablotronReadStream:
	def __init__(self, serial_port: str, *stop_events: threading.Event) -> None:
		self._stop_events = stop_events
		self._stream = open(serial_port, "rb", buffering=0)
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