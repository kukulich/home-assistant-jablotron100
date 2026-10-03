from __future__ import annotations

import errno
import os
import select
import stat
import sys
import threading
from unittest.mock import patch

import pytest

from custom_components.jablotron100.jablotron import Jablotron
from custom_components.jablotron100.stream import open_serial_port


@pytest.mark.parametrize("direction", ["read", "write"])
@pytest.mark.parametrize("existing", [False, True])
def test_stream_rejects_non_devices_without_creating_or_truncating_files(tmp_path, direction, existing):
	serial_port = tmp_path / "hidraw0"
	contents = b"not a device"
	if existing:
		serial_port.write_bytes(contents)
	jablotron = object.__new__(Jablotron)
	jablotron._serial_port = str(serial_port)
	jablotron._stream_stop_event = threading.Event()

	with pytest.raises(OSError) as error:
		stream = getattr(jablotron, f"_open_{direction}_stream")()
		stream.close()

	assert error.value.filename == str(serial_port)
	if existing:
		assert error.value.errno == errno.ENODEV
		assert "not a character device" in str(error.value)
		assert serial_port.read_bytes() == contents
	else:
		assert error.value.errno == errno.ENOENT
		assert not serial_port.exists()


@pytest.mark.parametrize("mode", ["rb", "wb"])
def test_open_serial_port_accepts_character_devices(mode):
	with open_serial_port(os.devnull, mode) as stream:
		assert stat.S_ISCHR(os.fstat(stream.fileno()).st_mode)
		if mode == "rb":
			assert stream.read(64) == b""
		else:
			assert stream.write(b"\x30\x01\x02") == 3
	assert stream.closed


def test_write_stream_delivers_packet_to_character_device(serial_device):
	serial_port, read_fd = serial_device
	jablotron = object.__new__(Jablotron)
	jablotron._serial_port = serial_port
	packet = b"\x30\x01\x02\r\n\x1a"
	with jablotron._open_write_stream() as stream:
		assert stream.write(packet) == len(packet)

	readable, _, _ = select.select([read_fd], [], [], 1)
	assert readable
	assert os.read(read_fd, 64) == packet


@pytest.mark.parametrize("mode", ["rb", "wb"])
def test_open_serial_port_validates_open_descriptor_and_closes_on_rejection(tmp_path, mode):
	serial_port = tmp_path / "replaced-device"
	contents = b"preserve this file"
	serial_port.write_bytes(contents)
	real_open = os.open
	opened = []

	def replaced_device(path, flags):
		assert path == os.devnull
		assert not flags & (os.O_CREAT | os.O_TRUNC)
		fd = real_open(serial_port, flags)
		opened.append(fd)
		return fd

	with patch("custom_components.jablotron100.stream.os.open", side_effect=replaced_device):
		with pytest.raises(OSError, match="not a character device"):
			open_serial_port(os.devnull, mode)

	assert serial_port.read_bytes() == contents
	assert len(opened) == 1
	with pytest.raises(OSError) as error:
		os.fstat(opened[0])
	assert error.value.errno == errno.EBADF


@pytest.mark.parametrize("failure", ["fstat", "fdopen"])
def test_open_serial_port_closes_descriptor_on_initialization_failure(failure):
	real_open = os.open
	real_fstat = os.fstat
	opened = []
	failure_error = OSError("Synthetic stream initialization failure")

	def record_open(path, flags):
		fd = real_open(path, flags)
		opened.append(fd)
		return fd

	with (
		patch("custom_components.jablotron100.stream.os.open", side_effect=record_open),
		patch(f"custom_components.jablotron100.stream.os.{failure}", side_effect=failure_error),
	):
		with pytest.raises(OSError) as error:
			open_serial_port(os.devnull, "wb")
		assert error.value is failure_error

	assert len(opened) == 1
	with pytest.raises(OSError) as error:
		real_fstat(opened[0])
	assert error.value.errno == errno.EBADF


@pytest.mark.skipif(sys.platform != "linux", reason="Uses device symlinks like udev")
@pytest.mark.parametrize("mode", ["rb", "wb"])
@pytest.mark.parametrize("connected", [False, True])
def test_open_serial_port_follows_device_symlinks_without_creating_missing_targets(tmp_path, mode, connected):
	target = os.devnull if connected else str(tmp_path / "missing-device")
	serial_port = tmp_path / "jablotron"
	serial_port.symlink_to(target)

	if connected:
		with open_serial_port(str(serial_port), mode) as stream:
			assert stat.S_ISCHR(os.fstat(stream.fileno()).st_mode)
	else:
		with pytest.raises(FileNotFoundError):
			open_serial_port(str(serial_port), mode)
		assert not os.path.exists(target)
	assert serial_port.is_symlink()


@pytest.mark.parametrize("port_type", ["missing", "regular", "character"])
def test_autodetection_requires_character_device(tmp_path, caplog, port_type):
	serial_port = tmp_path / "hidraw0"
	if port_type == "regular":
		serial_port.write_bytes(b"stale detection packet")
	elif port_type == "character":
		serial_port = os.devnull

	with patch(
		"custom_components.jablotron100.jablotron.os.path.realpath",
		return_value="0003:16D6:0008.0001",
	):
		assert Jablotron._is_jablotron_serial_port(str(serial_port)) is (port_type == "character")

	if port_type == "regular":
		assert "not a character device" in caplog.text
		assert str(serial_port) in caplog.text


def test_autodetection_still_rejects_other_usb_devices():
	with patch(
		"custom_components.jablotron100.jablotron.os.path.realpath",
		return_value="0003:1234:5678.0001",
	):
		assert not Jablotron._is_jablotron_serial_port(os.devnull)
