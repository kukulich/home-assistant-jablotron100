from __future__ import annotations

import pytest

from custom_components.jablotron100.const import DeviceConnection, SIGNAL_STRENGTH_STEP
from custom_components.jablotron100.jablotron import Jablotron


def captured_packet(
	packet: str,
	device_number: int,
	connection: DeviceConnection,
	signal_strength: int | None,
	battery_level: int | None,
	battery_ok: bool | None,
	packet_id: str,
):
	return pytest.param(
		packet,
		device_number,
		connection,
		signal_strength,
		battery_level,
		battery_ok,
		id=packet_id,
	)


CAPTURED_DEVICE_STATUS_PACKETS = [
	captured_packet("52078a0003000000f2", 0, DeviceConnection.WIRED, None, None, None, "device-0"),
	captured_packet("52078a0104000000f2", 1, DeviceConnection.WIRED, None, None, None, "device-1"),
	captured_packet("52078a0204200000f2", 2, DeviceConnection.WIRED, None, None, None, "device-2"),
	captured_packet("52078a0306200000fc", 3, DeviceConnection.WIRED, None, None, None, "device-3"),
	captured_packet("52078a0404200000f2", 4, DeviceConnection.WIRED, None, None, None, "device-4"),
	captured_packet("52078a0506200000fc", 5, DeviceConnection.WIRED, None, None, None, "device-5"),
	captured_packet("52078a0604200000f2", 6, DeviceConnection.WIRED, None, None, None, "device-6"),
	captured_packet("52078a0706200000fc", 7, DeviceConnection.WIRED, None, None, None, "device-7"),
	captured_packet("52078a0804200000f2", 8, DeviceConnection.WIRED, None, None, None, "device-8"),
	captured_packet("52078a0906200000fc", 9, DeviceConnection.WIRED, None, None, None, "device-9"),
	captured_packet("52078a0a04200000f2", 10, DeviceConnection.WIRED, None, None, None, "device-10"),
	captured_packet("52078a0b06200000fc", 11, DeviceConnection.WIRED, None, None, None, "device-11"),
	captured_packet("52078a0c04200000f2", 12, DeviceConnection.WIRED, None, None, None, "device-12"),
	captured_packet("52078a0d06200000fc", 13, DeviceConnection.WIRED, None, None, None, "device-13"),
	captured_packet("52078a0e04200000f2", 14, DeviceConnection.WIRED, None, None, None, "device-14"),
	captured_packet("52078a0f06200000fc", 15, DeviceConnection.WIRED, None, None, None, "device-15"),
	captured_packet("52078a1004200000f2", 16, DeviceConnection.WIRED, None, None, None, "device-16"),
	captured_packet("52078a1106200000fc", 17, DeviceConnection.WIRED, None, None, None, "device-17"),
	captured_packet("52078a1204200000f2", 18, DeviceConnection.WIRED, None, None, None, "device-18"),
	captured_packet("52078a1306200000fc", 19, DeviceConnection.WIRED, None, None, None, "device-19"),
	captured_packet("52078a1404000000f2", 20, DeviceConnection.WIRED, None, None, None, "device-20"),
	captured_packet("52078a1504000000f2", 21, DeviceConnection.WIRED, None, None, None, "device-21"),
	captured_packet("52078a1604000000f2", 22, DeviceConnection.WIRED, None, None, None, "device-22"),
	captured_packet("52078a1704000000f2", 23, DeviceConnection.WIRED, None, None, None, "device-23"),
	captured_packet("52098a180410b301fcab0a", 24, DeviceConnection.WIRELESS, 55, 100, True, "device-24"),
	captured_packet("52078a1907000f00fc", 25, DeviceConnection.WIRED, None, None, None, "device-25"),
	captured_packet("52098a1a03200600fceb0a", 26, DeviceConnection.WIRELESS, 55, 100, True, "device-26"),
	captured_packet("52098a1b03201d00fcaf0a", 27, DeviceConnection.WIRELESS, 75, 100, True, "device-27"),
	captured_packet("52098a1c0320b101fc340a", 28, DeviceConnection.WIRELESS, 100, 100, True, "device-28"),
	captured_packet("52098a1d03201000fcb40a", 29, DeviceConnection.WIRELESS, 100, 100, True, "device-29"),
	captured_packet("52098a1e03200a00fcca0a", 30, DeviceConnection.WIRELESS, 50, 100, True, "device-30"),
	captured_packet("52078a1f04000000f2", 31, DeviceConnection.WIRED, None, None, None, "device-31"),
	# The trailing 00 bytes in the capture are stream padding outside the length-delimited packets.
	captured_packet("52078a2000000f00fc", 32, DeviceConnection.WIRED, None, None, None, "unused-device-32"),
	captured_packet("52078a2100000f00fc", 33, DeviceConnection.WIRED, None, None, None, "unused-device-33"),
	captured_packet("52078a2200000f00fc", 34, DeviceConnection.WIRED, None, None, None, "unused-device-34"),
	captured_packet("52078a2300000f00fc", 35, DeviceConnection.WIRED, None, None, None, "unused-device-35"),
	captured_packet("52078a2400000f00fc", 36, DeviceConnection.WIRED, None, None, None, "unused-device-36"),
	captured_packet("52098a240c00d700fc6a0c", 36, DeviceConnection.WIRELESS, 50, None, None, "pulse-meter-36"),
	captured_packet("52098a250c001900fcaa0c", 37, DeviceConnection.WIRELESS, 50, None, None, "pulse-meter-37"),
	captured_packet("52098a184610fffffc4d08", 24, DeviceConnection.WIRELESS, 65, 80, True, "low-battery-device-24"),
	captured_packet("52098a7fd56423d2af0101", 127, DeviceConnection.WIRELESS, 5, 10, True, "gsm"),
	captured_packet("52088a7da683c0a80163", 125, DeviceConnection.WIRED, None, None, None, "lan"),
	captured_packet(
		"52188a7c0a888a008803008a108800008a118800008a01887200",
		124,
		DeviceConnection.WIRED,
		None,
		None,
		None,
		"central-unit-power",
	),
]


@pytest.mark.parametrize(
	(
		"packet_hex",
		"expected_device_number",
		"expected_connection",
		"expected_signal_strength",
		"expected_battery_level",
		"expected_battery_ok",
	),
	CAPTURED_DEVICE_STATUS_PACKETS,
)
def test_parse_captured_device_status_packet(
	packet_hex: str,
	expected_device_number: int,
	expected_connection: DeviceConnection,
	expected_signal_strength: int | None,
	expected_battery_level: int | None,
	expected_battery_ok: bool | None,
) -> None:
	packet = bytes.fromhex(packet_hex)

	assert len(packet) == packet[1] + 2
	assert Jablotron._is_device_status_packet(packet)
	assert Jablotron._parse_device_number_from_device_status_packet(packet) == expected_device_number
	assert Jablotron._parse_device_connection_type_from_device_status_packet(packet) == expected_connection

	if expected_connection == DeviceConnection.WIRED:
		return

	assert Jablotron._parse_device_signal_strength_from_device_status_packet(packet) == expected_signal_strength
	assert expected_signal_strength is None or expected_signal_strength % SIGNAL_STRENGTH_STEP == 0

	battery_state = Jablotron._parse_device_battery_level_from_device_status_packet(packet)
	if expected_battery_level is None:
		assert battery_state is None
	else:
		assert battery_state is not None
		assert battery_state.level == expected_battery_level
		assert battery_state.ok == expected_battery_ok
