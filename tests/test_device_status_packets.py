from __future__ import annotations

import threading
from unittest.mock import Mock

from homeassistant.const import CONF_PASSWORD
import pytest

from custom_components.jablotron100.const import (
	CONF_DEVICES,
	CONF_NUMBER_OF_DEVICES,
	DeviceConnection,
	DeviceData,
	DeviceType,
	PACKET_DEVICES_SECTIONS,
	PACKET_GET_DEVICES_SECTIONS,
	SIGNAL_STRENGTH_STEP,
)
from custom_components.jablotron100.errors import ServiceUnavailable, ShouldNotHappen
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


@pytest.fixture
def discovery():
	jablotron = object.__new__(Jablotron)
	jablotron._config = {CONF_PASSWORD: "1234"}
	jablotron._devices_data = {}
	jablotron._get_not_ignored_devices = Mock(return_value=[1, 2])
	jablotron._send_packet = Mock()
	jablotron._send_packets = Mock()
	jablotron._store_devices_data = Mock()
	jablotron._log_incoming_packet = Mock()
	stream = Mock()
	jablotron._open_read_stream = Mock(return_value=stream)
	return jablotron, stream


@pytest.fixture
def blocking_discovery(discovery):
	jablotron, stream = discovery
	packets: list[bytes] = []

	def open_stream(stop_event):
		pending = iter(packets)

		def read(size):
			packet = next(pending, None)
			if packet is not None:
				return packet
			assert stop_event.wait(10), "Device discovery did not stop its idle reader"
			return None

		stream.read.side_effect = read
		return stream

	jablotron._open_read_stream.side_effect = open_stream
	return jablotron, stream, packets


DEVICE_ONE_STATUS = bytes.fromhex("52078a0104000000f2")
DEVICE_TWO_STATUS = bytes.fromhex("52078a0204200000f2")
UNREQUESTED_DEVICE_STATUS = bytes.fromhex("52078a0306200000fc")
DEVICE_SECTIONS = Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x01\x21")


@pytest.mark.parametrize("reads", [
	pytest.param([DEVICE_ONE_STATUS, DEVICE_ONE_STATUS, DEVICE_SECTIONS, DEVICE_TWO_STATUS], id="duplicate-status"),
	pytest.param([DEVICE_SECTIONS, DEVICE_SECTIONS, DEVICE_ONE_STATUS, DEVICE_TWO_STATUS], id="duplicate-sections"),
	pytest.param([UNREQUESTED_DEVICE_STATUS, DEVICE_ONE_STATUS, DEVICE_SECTIONS, DEVICE_TWO_STATUS], id="unrequested-device"),
	pytest.param([DEVICE_ONE_STATUS * 2 + DEVICE_SECTIONS + DEVICE_TWO_STATUS], id="duplicates-in-one-read"),
	pytest.param([DEVICE_TWO_STATUS, DEVICE_SECTIONS, DEVICE_ONE_STATUS], id="out-of-order"),
])
def test_discovery_requires_distinct_requested_devices(discovery, reads):
	jablotron, stream = discovery
	stream.read.side_effect = [*reads, None]
	jablotron._detect_devices()
	assert set(jablotron._devices_data) == {"device_1", "device_2"}
	assert jablotron._devices_data["device_1"][DeviceData.SECTION] == 2
	assert jablotron._devices_data["device_2"][DeviceData.SECTION] == 3
	jablotron._store_devices_data.assert_called_once_with()
	stream.close.assert_called_once_with()


def test_equal_size_cache_with_different_device_ids_is_rediscovered(discovery):
	jablotron, stream = discovery
	jablotron._devices_data = {"device_1": {DeviceData.SECTION: 1}, "device_3": {DeviceData.SECTION: 1}}
	stream.read.side_effect = [DEVICE_ONE_STATUS, DEVICE_TWO_STATUS, DEVICE_SECTIONS, None]
	jablotron._detect_devices()
	assert set(jablotron._devices_data) == {"device_1", "device_2"}
	assert jablotron._devices_data["device_1"][DeviceData.SECTION] == 2
	jablotron._store_devices_data.assert_called_once_with()


def test_missing_device_response_does_not_replace_previous_cache(discovery):
	jablotron, stream = discovery
	previous_data = {"device_9": {DeviceData.SECTION: 4}}
	jablotron._devices_data = previous_data.copy()
	stream.read.side_effect = [DEVICE_ONE_STATUS, DEVICE_ONE_STATUS, DEVICE_SECTIONS, None]
	with pytest.raises(ShouldNotHappen):
		jablotron._detect_devices()
	assert jablotron._devices_data == previous_data
	jablotron._store_devices_data.assert_not_called()
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("complete", [False, True])
def test_only_complete_matching_cache_skips_discovery(discovery, complete):
	jablotron, stream = discovery
	jablotron._devices_data = {
		f"device_{number}": {
			DeviceData.CONNECTION: DeviceConnection.WIRED,
			DeviceData.SIGNAL_STRENGTH: None,
			DeviceData.BATTERY: False,
			DeviceData.BATTERY_LEVEL: None,
			DeviceData.SECTION: number + 1 if complete else None,
		}
		for number in (1, 2)
	}
	stream.read.side_effect = [DEVICE_ONE_STATUS, DEVICE_TWO_STATUS, DEVICE_SECTIONS, None]
	jablotron._detect_devices()
	if complete:
		jablotron._open_read_stream.assert_not_called()
		jablotron._store_devices_data.assert_not_called()
	else:
		assert jablotron._devices_data["device_2"][DeviceData.SECTION] == 3
		jablotron._store_devices_data.assert_called_once_with()


def test_discovery_waits_for_map_covering_highest_requested_device(discovery):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = [1, 3]
	full_map = Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x01\x21\x03")
	stream.read.side_effect = [DEVICE_ONE_STATUS, UNREQUESTED_DEVICE_STATUS, DEVICE_SECTIONS, full_map, None]
	jablotron._detect_devices()
	assert set(jablotron._devices_data) == {"device_1", "device_3"}
	assert jablotron._devices_data["device_3"][DeviceData.SECTION] == 4


def test_discovery_clears_cache_when_all_devices_are_ignored(discovery):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = []
	jablotron._devices_data = {"device_1": {DeviceData.SECTION: 1}}
	jablotron._detect_devices()
	assert jablotron._devices_data == {}
	jablotron._open_read_stream.assert_not_called()
	jablotron._store_devices_data.assert_called_once_with()


def test_missing_section_map_does_not_replace_previous_cache(discovery):
	jablotron, stream = discovery
	previous_data = {"device_9": {DeviceData.SECTION: 4}}
	jablotron._devices_data = previous_data.copy()
	stream.read.side_effect = [DEVICE_ONE_STATUS, DEVICE_TWO_STATUS, None]
	with pytest.raises(ShouldNotHappen):
		jablotron._detect_devices()
	assert jablotron._devices_data == previous_data
	jablotron._store_devices_data.assert_not_called()


@pytest.mark.parametrize("packets,expected_details", [
	pytest.param(
		[DEVICE_ONE_STATUS, DEVICE_ONE_STATUS, UNREQUESTED_DEVICE_STATUS, DEVICE_SECTIONS],
		["Missing status replies for positions: [2].", "Section map covers 2 positions (4 bytes)"],
		id="missing-status-despite-duplicate-and-unrequested-replies",
	),
	pytest.param(
		[DEVICE_ONE_STATUS, DEVICE_TWO_STATUS],
		["Missing status replies for positions: none.", "No complete section map received"],
		id="missing-section-map",
	),
	pytest.param(
		[DEVICE_ONE_STATUS, DEVICE_TWO_STATUS, DEVICE_SECTIONS[:-1]],
		["Missing status replies for positions: none.", "No complete section map received"],
		id="truncated-section-map",
	),
	pytest.param(
		[DEVICE_ONE_STATUS, DEVICE_TWO_STATUS, bytes.fromhex("3b00")],
		["Missing status replies for positions: none.", "No complete section map received"],
		id="section-map-without-start-position",
	),
	pytest.param(
		[],
		["Missing status replies for positions: [1, 2].", "No complete section map received"],
		id="no-replies",
	),
	pytest.param(
		[DEVICE_ONE_STATUS, bytes.fromhex("3b0101")],
		[
			"Missing status replies for positions: [2].",
			"Section map covers 0 positions (3 bytes)",
			"Positions missing from section map: [1, 2].",
		],
		id="missing-status-and-empty-section-map",
	),
])
def test_discovery_timeout_reports_missing_data(blocking_discovery, caplog, packets, expected_details):
	jablotron, stream, pending = blocking_discovery
	previous_data = {"device_9": {DeviceData.SECTION: 4}}
	jablotron._devices_data = previous_data.copy()
	jablotron._config[CONF_PASSWORD] = "12*4826"
	pending.extend(packets)

	with pytest.raises(ServiceUnavailable) as error:
		jablotron._detect_devices()

	message = str(error.value)
	assert message.startswith("Device discovery timed out.")
	for detail in expected_details:
		assert detail in message
	assert isinstance(error.value.__cause__, TimeoutError)
	assert caplog.messages == [f"Service unavailable: {message}"]
	assert "12*4826" not in caplog.text
	assert Jablotron.create_packet_authorisation_code("12*4826")[3:].hex() not in caplog.text
	assert jablotron._devices_data == previous_data
	jablotron._store_devices_data.assert_not_called()
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("slot_29_type,complete_map_later", [
	pytest.param(DeviceType.KEY_FOB, False, id="stale-position-29-times-out"),
	pytest.param(DeviceType.EMPTY, False, id="empty-position-29-succeeds"),
	pytest.param(DeviceType.KEY_FOB, True, id="complete-map-after-short-map-succeeds"),
])
def test_discovery_section_map_boundary_at_position_29(blocking_discovery, caplog, slot_29_type, complete_map_later):
	jablotron, stream, pending = blocking_discovery
	jablotron._config[CONF_NUMBER_OF_DEVICES] = 29
	jablotron._config[CONF_DEVICES] = [DeviceType.EMPTY.value] * 27 + [DeviceType.KEY_FOB.value, slot_29_type.value]
	del jablotron._get_not_ignored_devices
	previous_data = {"device_9": {DeviceData.SECTION: 4}}
	jablotron._devices_data = previous_data.copy()

	# Captured JA-103K replies from upstream issue 170; other positions are isolated out.
	section_map = bytes.fromhex("3b0f010000000000000000000000000000")
	assert len(section_map) == section_map[1] + 2 == 17
	pending.extend([
		bytes.fromhex("52098a1c0600fffffc8e0e"),
		bytes.fromhex("52078a1d00000f00fc"),
		section_map,
		DEVICE_SECTIONS,
	])
	if complete_map_later:
		pending.append(Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x01" + b"\x00" * 15))

	if slot_29_type == DeviceType.KEY_FOB and not complete_map_later:
		with pytest.raises(ServiceUnavailable) as error:
			jablotron._detect_devices()
		message = str(error.value)
		assert "Missing status replies for positions: none." in message
		assert "Section map covers 28 positions (17 bytes)" in message
		assert "expected coverage through position 29 (at least 18 bytes)" in message
		assert "Positions missing from section map: [29]." in message
		assert "F-Link/J-Link" in message
		assert "Empty" in message
		assert "Reconfigure" in message
		assert caplog.messages == [f"Service unavailable: {message}"]
		assert jablotron._devices_data == previous_data
		jablotron._store_devices_data.assert_not_called()
	else:
		jablotron._detect_devices()
		expected_numbers = [28] if slot_29_type == DeviceType.EMPTY else [28, 29]
		assert jablotron._get_not_ignored_devices() == expected_numbers
		assert set(jablotron._devices_data) == {f"device_{number}" for number in expected_numbers}
		assert all(data[DeviceData.SECTION] == 1 for data in jablotron._devices_data.values())
		jablotron._store_devices_data.assert_called_once_with()
		assert caplog.messages == []
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("read_error", [OSError("Synthetic read failure"), FileNotFoundError("Synthetic read failure")])
def test_discovery_read_errors_are_not_reported_as_timeouts(discovery, caplog, read_error):
	jablotron, stream = discovery
	stream.read.side_effect = read_error
	with pytest.raises(ServiceUnavailable):
		jablotron._detect_devices()
	assert caplog.messages == ["Service unavailable: Synthetic read failure"]
	jablotron._store_devices_data.assert_not_called()
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("complete", [False, True])
def test_discovery_preserves_and_collects_identification(discovery, complete):
	jablotron, stream = discovery
	previous_data = {
		"device_1": {DeviceData.MODEL: "JA-OLD", DeviceData.HARDWARE_VERSION: "HW1"},
		"device_3": {DeviceData.MODEL: "removed"},
	}
	jablotron._devices_data = previous_data.copy()
	device_one_info = Jablotron.create_packet(b"\x90", bytes.fromhex("014005024a412d58"))
	ignored_device_info = Jablotron.create_packet(b"\x90", bytes.fromhex("034005024a412d59"))
	stream.read.side_effect = [
		device_one_info, ignored_device_info, DEVICE_ONE_STATUS,
		DEVICE_SECTIONS, *([DEVICE_TWO_STATUS] if complete else []), None,
	]
	if not complete:
		with pytest.raises(ShouldNotHappen):
			jablotron._detect_devices()
		assert jablotron._devices_data == previous_data
		jablotron._store_devices_data.assert_not_called()
		return

	jablotron._detect_devices()
	assert jablotron._devices_data["device_1"][DeviceData.MODEL] == "JA-X"
	assert jablotron._devices_data["device_1"][DeviceData.HARDWARE_VERSION] == "HW1"
	assert DeviceData.FIRMWARE_VERSION not in jablotron._devices_data["device_1"]
	assert set(jablotron._devices_data) == {"device_1", "device_2"}
	jablotron._store_devices_data.assert_called_once_with()


# Captured JA-107K replies and F-Link references from upstream issue 174.
JA107K_SECTIONS_1_122 = bytes.fromhex(
	"3b3e0103000000000000000000002292222222222222222222220001110433333355550050004400000629222202000000007077a0aa00a000aa000000333323"
)
JA107K_SECTIONS_123_219 = bytes.fromhex(
	"3b327b22090000000000000000000000000000000000000030949949040000000300000000000000000000000000000010111101"
)
JA107K_STATUS_PACKETS = [
	bytes.fromhex("52078a0104000000f3"),
	bytes.fromhex("52078aa604000000f3"),
	bytes.fromhex("52078ac804200000f3"),
	bytes.fromhex("52078ad64600fffffc"),
	bytes.fromhex("52078adb04000000f2"),
]
JA107K_EXPECTED_SECTIONS = {1: 4, 166: 4, 200: 1, 214: 2, 219: 2}


@pytest.mark.parametrize("maps", [
	pytest.param([JA107K_SECTIONS_1_122, JA107K_SECTIONS_123_219], id="in-order"),
	pytest.param([JA107K_SECTIONS_123_219, JA107K_SECTIONS_1_122], id="reversed"),
	pytest.param([JA107K_SECTIONS_1_122, JA107K_SECTIONS_1_122, JA107K_SECTIONS_123_219], id="duplicate-prefix"),
	pytest.param([JA107K_SECTIONS_123_219, JA107K_SECTIONS_123_219, JA107K_SECTIONS_1_122], id="duplicate-suffix"),
	pytest.param(
		[JA107K_SECTIONS_1_122, Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x7b\x22"), JA107K_SECTIONS_123_219],
		id="short-suffix-then-full",
	),
])
def test_discovery_combines_captured_section_map_ranges(discovery, caplog, maps):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = list(JA107K_EXPECTED_SECTIONS)
	stream.read.side_effect = [*JA107K_STATUS_PACKETS, *maps, None]

	jablotron._detect_devices()

	assert set(jablotron._devices_data) == {f"device_{number}" for number in JA107K_EXPECTED_SECTIONS}
	assert {
		number: jablotron._devices_data[f"device_{number}"][DeviceData.SECTION]
		for number in JA107K_EXPECTED_SECTIONS
	} == JA107K_EXPECTED_SECTIONS
	assert caplog.messages == []
	jablotron._store_devices_data.assert_called_once_with()
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("highest,expected_requests", [
	pytest.param(1, ["3a020101"], id="single-odd-position"),
	pytest.param(29, ["3a02011d"], id="small-odd-range"),
	pytest.param(122, ["3a02017a"], id="last-single-packet-position"),
	pytest.param(123, ["3a02017a", "3a027b7b"], id="first-two-packet-position"),
	pytest.param(219, ["3a02017a", "3a027bdb"], id="reported-odd-end"),
	pytest.param(220, ["3a02017a", "3a027bdc"], id="padding-becomes-requested-position"),
	pytest.param(230, ["3a02017a", "3a027be6"], id="maximum-configured-position"),
])
def test_discovery_requests_bounded_inclusive_ranges(discovery, highest, expected_requests):
	jablotron, stream = discovery
	numbers = [highest] if highest == 1 else [1, highest]
	jablotron._get_not_ignored_devices.return_value = numbers
	sent = threading.Event()
	jablotron._send_packets.side_effect = lambda packets: sent.set()
	replies = [
		Jablotron.create_packet(b"\x52", bytes((0x8a, number, 4, 0, 0, 0, 0xf2)))
		for number in numbers
	]
	for request in expected_requests:
		_, _, start, end = bytes.fromhex(request)
		data = b"\x21" * ((end - start + 2) // 2)
		replies.append(Jablotron.create_packet(PACKET_DEVICES_SECTIONS, bytes((start,)) + data))
	pending = iter(replies)

	def read(size):
		assert size == 64
		assert sent.wait(5), "Device discovery did not send its requests"
		packet = next(pending, None)
		assert packet is None or len(packet) <= size
		return packet

	stream.read.side_effect = read
	jablotron._detect_devices()

	jablotron._send_packets.assert_called_once()
	requests = [packet for packet in jablotron._send_packets.call_args.args[0] if packet[:1] == PACKET_GET_DEVICES_SECTIONS]
	assert requests == [bytes.fromhex(packet) for packet in expected_requests]
	assert all(1 <= packet[2] <= packet[3] <= highest and packet[2] % 2 == 1 for packet in requests)
	assert all(3 + (packet[3] - packet[2] + 2) // 2 <= 64 for packet in requests)
	assert {position for packet in requests for position in range(packet[2], packet[3] + 1)} == set(range(1, highest + 1))
	assert set(jablotron._devices_data) == {f"device_{number}" for number in numbers}
	assert jablotron._devices_data[f"device_{highest}"][DeviceData.SECTION] == (2 if highest % 2 else 3)
	jablotron._store_devices_data.assert_called_once_with()
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("missing", ["prefix", "suffix", "status"])
def test_incomplete_multi_range_discovery_preserves_cache(discovery, missing):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = list(JA107K_EXPECTED_SECTIONS)
	previous_data = {"device_9": {DeviceData.SECTION: 4}}
	jablotron._devices_data = previous_data.copy()
	statuses = JA107K_STATUS_PACKETS[:-1] if missing == "status" else JA107K_STATUS_PACKETS
	maps = {
		"prefix": [JA107K_SECTIONS_123_219, JA107K_SECTIONS_123_219],
		"suffix": [JA107K_SECTIONS_1_122, JA107K_SECTIONS_1_122],
		"status": [JA107K_SECTIONS_1_122, JA107K_SECTIONS_123_219],
	}[missing]
	stream.read.side_effect = [*statuses, *maps, None]

	with pytest.raises(ShouldNotHappen):
		jablotron._detect_devices()

	assert jablotron._devices_data == previous_data
	jablotron._store_devices_data.assert_not_called()
	stream.close.assert_called_once_with()


@pytest.mark.parametrize("packet,reason", [
	pytest.param(b"\x3b", "malformed", id="missing-length"),
	pytest.param(b"\x3b\x00", "malformed", id="missing-start"),
	pytest.param(JA107K_SECTIONS_123_219[:-1], "malformed", id="truncated"),
	pytest.param(Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x7b" + b"\x11" * 62), "malformed", id="larger-than-hid-read"),
	pytest.param(Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x00" + b"\x11" * 61), "unrequested", id="zero-start"),
	pytest.param(Jablotron.create_packet(PACKET_DEVICES_SECTIONS, b"\x02" + b"\x11" * 61), "unrequested", id="even-start"),
	pytest.param(bytes.fromhex("3b03792322"), "unrequested", id="overlapping-unrequested-start"),
	pytest.param(bytes.fromhex("3b02ff11"), "unrequested", id="start-outside-configured-positions"),
])
def test_discovery_ignores_invalid_or_unrequested_map_ranges(discovery, caplog, packet, reason):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = list(JA107K_EXPECTED_SECTIONS)
	stream.read.side_effect = [*JA107K_STATUS_PACKETS, packet, JA107K_SECTIONS_123_219, JA107K_SECTIONS_1_122, None]
	with caplog.at_level("DEBUG", logger="custom_components.jablotron100"):
		jablotron._detect_devices()

	assert any(f"Ignoring {reason} device section-map packet" in message for message in caplog.messages)
	assert {
		number: jablotron._devices_data[f"device_{number}"][DeviceData.SECTION]
		for number in JA107K_EXPECTED_SECTIONS
	} == JA107K_EXPECTED_SECTIONS
	jablotron._store_devices_data.assert_called_once_with()
	stream.close.assert_called_once_with()


def test_discovery_accepts_longer_map_without_assigning_unrequested_positions(discovery):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = [1, 3]
	stream.read.side_effect = [DEVICE_ONE_STATUS, UNREQUESTED_DEVICE_STATUS, JA107K_SECTIONS_1_122, None]
	jablotron._detect_devices()
	assert set(jablotron._devices_data) == {"device_1", "device_3"}
	assert jablotron._devices_data["device_1"][DeviceData.SECTION] == 4
	assert jablotron._devices_data["device_3"][DeviceData.SECTION] == 1


@pytest.mark.parametrize("map_packet,received_range,missing_sections", [
	pytest.param(JA107K_SECTIONS_1_122, (1, 122), [166, 200, 214, 219], id="missing-second-range"),
	pytest.param(JA107K_SECTIONS_123_219, (123, 219), [1], id="missing-first-range-and-ignore-padding-220"),
])
def test_discovery_timeout_reports_actual_map_ranges(blocking_discovery, caplog, map_packet, received_range, missing_sections):
	jablotron, stream, pending = blocking_discovery
	jablotron._get_not_ignored_devices.return_value = list(JA107K_EXPECTED_SECTIONS)
	jablotron._config[CONF_PASSWORD] = "12*4826"
	previous_data = {"device_9": {DeviceData.SECTION: 4}}
	jablotron._devices_data = previous_data.copy()
	pending.extend([*JA107K_STATUS_PACKETS, map_packet, map_packet])

	with pytest.raises(ServiceUnavailable) as error:
		jablotron._detect_devices()

	message = str(error.value)
	assert isinstance(error.value.__cause__, TimeoutError)
	assert "Missing status replies for positions: none." in message
	assert f"Section-map ranges received: {[received_range]}" in message
	assert "requested ranges: [(1, 122), (123, 219)]" in message
	assert f"Positions missing from section map: {missing_sections}." in message
	assert "113 bytes" not in message
	assert "220" not in message
	assert caplog.messages == [f"Service unavailable: {message}"]
	assert "12*4826" not in caplog.text
	assert Jablotron.create_packet_authorisation_code("12*4826")[3:].hex() not in caplog.text
	assert jablotron._devices_data == previous_data
	jablotron._store_devices_data.assert_not_called()
	stream.close.assert_called_once_with()


def test_complete_multi_range_cache_skips_rediscovery(discovery):
	jablotron, stream = discovery
	jablotron._get_not_ignored_devices.return_value = list(JA107K_EXPECTED_SECTIONS)
	stream.read.side_effect = [*JA107K_STATUS_PACKETS, JA107K_SECTIONS_123_219, JA107K_SECTIONS_1_122, None]
	jablotron._detect_devices()
	jablotron._open_read_stream.reset_mock()
	jablotron._send_packet.reset_mock()
	jablotron._send_packets.reset_mock()
	jablotron._store_devices_data.reset_mock()

	jablotron._detect_devices()

	jablotron._open_read_stream.assert_not_called()
	jablotron._send_packet.assert_not_called()
	jablotron._send_packets.assert_not_called()
	jablotron._store_devices_data.assert_not_called()
