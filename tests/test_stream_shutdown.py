from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import os
import sys
import threading
from unittest.mock import Mock

import pytest

from custom_components.jablotron100.jablotron import Jablotron
from custom_components.jablotron100.const import DeviceType
from custom_components.jablotron100.stream import JablotronReadStream


pytestmark = pytest.mark.skipif(sys.platform != "linux", reason="Uses Linux file descriptors like hidraw")


def test_shutdown_stops_idle_reader_without_another_packet():
	read_fd, write_fd = os.pipe()
	jablotron = object.__new__(Jablotron)
	jablotron._serial_port = f"/proc/self/fd/{read_fd}"
	jablotron._stream_stop_event = threading.Event()
	jablotron._stream_data_updating_event = threading.Event()
	jablotron._stream_diagnostics_event = threading.Event()
	jablotron._login_failed = threading.Event()
	jablotron.last_update_success = True
	jablotron._set_unavailable = Mock()
	jablotron._redetect_serial_port = Mock()
	reading = threading.Event()
	closed = threading.Event()
	open_stream = jablotron._open_read_stream

	class ObservedStream:
		def __init__(self):
			self.stream = open_stream()

		def read(self, size):
			reading.set()
			return self.stream.read(size)

		def close(self):
			self.stream.close()
			closed.set()

	jablotron._open_read_stream = ObservedStream
	executor = ThreadPoolExecutor(max_workers=1)
	jablotron._stream_thread_pool_executor = executor
	reader = executor.submit(jablotron._read_packets)
	try:
		assert reading.wait(5)
		jablotron.shutdown()
		reader.result(timeout=1)
		assert closed.is_set()
		jablotron._set_unavailable.assert_not_called()
		jablotron._redetect_serial_port.assert_not_called()
	finally:
		jablotron._stream_stop_event.set()
		os.write(write_fd, b"\x00")
		executor.shutdown(wait=True, cancel_futures=True)
		os.close(read_fd)
		os.close(write_fd)


@pytest.mark.parametrize("result", ["data", "eof", "stop"])
def test_read_stream_distinguishes_data_eof_and_cancellation(result):
	read_fd, write_fd = os.pipe()
	stop_event = threading.Event()
	stream = JablotronReadStream(f"/proc/self/fd/{read_fd}", stop_event)
	try:
		if result == "eof":
			os.close(write_fd)
			write_fd = None
			assert stream.read(64) == b""
		else:
			packet = bytes.fromhex("500101")
			os.write(write_fd, packet)
			if result == "stop":
				stop_event.set()
				assert stream.read(64) is None
			else:
				assert stream.read(64) == packet
	finally:
		stream.close()
		os.close(read_fd)
		if write_fd is not None:
			os.close(write_fd)


def test_local_detection_stop_does_not_stop_running_instance():
	read_fd, write_fd = os.pipe()
	jablotron = object.__new__(Jablotron)
	jablotron._serial_port = f"/proc/self/fd/{read_fd}"
	jablotron._stream_stop_event = threading.Event()
	detection_stop = threading.Event()
	stream = jablotron._open_read_stream(detection_stop)
	try:
		detection_stop.set()
		assert stream.read(64) is None
		assert not jablotron._stream_stop_event.is_set()
	finally:
		stream.close()
		os.close(read_fd)
		os.close(write_fd)


def test_shutdown_interrupts_diagnostics_without_late_writes():
	jablotron = object.__new__(Jablotron)
	jablotron._stream_stop_event = threading.Event()
	jablotron._stream_data_updating_event = threading.Event()
	jablotron._stream_diagnostics_event = threading.Event()
	jablotron._get_not_ignored_devices = Mock(return_value=[1, 2])
	jablotron._get_device_type = Mock(return_value=DeviceType.THERMOMETER)
	jablotron._is_central_unit_103_or_similar = Mock(return_value=False)
	started = threading.Event()
	jablotron._send_packets = Mock(side_effect=lambda packets: started.set())
	jablotron._send_packet = Mock()
	executor = ThreadPoolExecutor(max_workers=1)
	jablotron._stream_thread_pool_executor = executor
	worker = executor.submit(jablotron._force_devices_info_update)
	try:
		assert started.wait(5)
		jablotron.shutdown()
		worker.result(timeout=1)
		jablotron._send_packets.assert_called_once()
		jablotron._send_packet.assert_not_called()
	finally:
		jablotron.shutdown()
		executor.shutdown(wait=True)


@pytest.mark.parametrize("stopped", [False, True])
def test_write_stream_closes_on_failure_and_does_not_open_after_stop(stopped):
	jablotron = object.__new__(Jablotron)
	jablotron._stream_stop_event = threading.Event()
	stream = Mock()
	stream.write.side_effect = OSError("Synthetic write failure")
	jablotron._open_write_stream = Mock(return_value=stream)
	if stopped:
		jablotron._stream_stop_event.set()
		jablotron._send_packet_by_stream(b"\x00")
		jablotron._open_write_stream.assert_not_called()
	else:
		with pytest.raises(OSError, match="Synthetic write failure"):
			jablotron._send_packet_by_stream(b"\x00")
		stream.close.assert_called_once_with()