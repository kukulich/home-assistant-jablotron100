from __future__ import annotations

from unittest.mock import Mock, call

import pytest

from custom_components.jablotron100.const import (
	DEVICE_INFO_KNOWN_SUBPACKETS,
	DeviceInfoType,
)
from custom_components.jablotron100.jablotron import Jablotron


def captured_packet(
	packet: str,
	device_number: int,
	battery_level: int | None,
	battery_ok: bool | None,
	info_types: tuple[DeviceInfoType, ...],
	packet_id: str,
):
	return pytest.param(
		packet,
		device_number,
		battery_level,
		battery_ok,
		info_types,
		id=packet_id,
	)


CAPTURED_DEVICE_INFO_PACKETS = [
	captured_packet("9005189c020a1d", 24, 100, True, (), "perimeter-device-24"),
	captured_packet("90051a9c020a1e", 26, 100, True, (), "perimeter-device-26"),
	captured_packet("90051b9c020a1e", 27, 100, True, (), "perimeter-device-27"),
	captured_packet("90051c9c02091e", 28, 90, True, (), "perimeter-device-28"),
	captured_packet("90051d9c020a1e", 29, 100, True, (), "perimeter-device-29"),
	captured_packet("90051e9c020a1e", 30, 100, True, (), "perimeter-device-30"),
	captured_packet("900be90a080f00a683c0a844e3", 233, None, None, (DeviceInfoType.LAN,), "lan"),
	captured_packet("900bea0a080f00a45023000001", 234, None, None, (DeviceInfoType.GSM,), "gsm"),
	captured_packet("900aeb0a070f008500000000", 235, None, None, (), "system-device-235"),
	captured_packet(
		"900d049c0a0ae66c00a3016c018c01",
		4,
		100,
		True,
		(DeviceInfoType.POWER_PRECISE, DeviceInfoType.POWER_PRECISE),
		"indoor-siren-with-battery",
	),
	captured_packet("9005170a020f88", 23, None, None, (), "indoor-siren"),
	captured_packet(
		"900f1f0a0c0a868a003900008a01380000",
		31,
		100,
		True,
		(DeviceInfoType.POWER, DeviceInfoType.POWER),
		"outdoor-siren",
	),
	captured_packet(
		"900d050a0a0a896c003f026c012f02",
		5,
		100,
		True,
		(DeviceInfoType.POWER_PRECISE, DeviceInfoType.POWER_PRECISE),
		"indoor-siren-device-5",
	),
	captured_packet("900a140a070f87831a002521", 20, None, None, (DeviceInfoType.SMOKE,), "smoke-device-20-a"),
	captured_packet("900a150a070f858319002521", 21, None, None, (DeviceInfoType.SMOKE,), "smoke-device-21-a"),
	captured_packet("900a1b0a0708878315002421", 27, 80, True, (DeviceInfoType.SMOKE,), "smoke-device-27"),
	captured_packet("900a159c070f858317002821", 21, None, None, (DeviceInfoType.SMOKE,), "smoke-device-21-b"),
	captured_packet("900a159c070f858316002821", 21, None, None, (DeviceInfoType.SMOKE,), "smoke-device-21-c"),
	captured_packet("900a199c070f87831d001f2a", 25, None, None, (DeviceInfoType.SMOKE,), "smoke-device-25"),
	captured_packet("900a149c070f878317002521", 20, None, None, (DeviceInfoType.SMOKE,), "smoke-device-20-b"),
	captured_packet(
		"9023249c200c3d9024671f40910000000091043203309029671f4091000000009107320330",
		36,
		None,
		None,
		(DeviceInfoType.PULSE,) * 4,
		"energy-device-36-a",
	),
	captured_packet(
		"9023249c200c3c909c671f409100000000911732033090a1671f4091000000009117320330",
		36,
		None,
		None,
		(DeviceInfoType.PULSE,) * 4,
		"energy-device-36-b",
	),
	captured_packet(
		"9023249c200c3d906023274091ec06002091a8b50310906523274091ec06002091a8b50310",
		36,
		None,
		None,
		(DeviceInfoType.PULSE,) * 4,
		"energy-device-36-c",
	),
	captured_packet(
		"9023259c200c3d90eb24274091fd02002091e992021090f024274091fd02002091e9920210",
		37,
		None,
		None,
		(DeviceInfoType.PULSE,) * 4,
		"energy-device-37-a",
	),
	captured_packet(
		"9023259c200c3d9063252740910203002091e99202109068252740910303002091e9920210",
		37,
		None,
		None,
		(DeviceInfoType.PULSE,) * 4,
		"energy-device-37-b",
	),
	captured_packet(
		"9023259c200c3d90172b274091240300209129930210901c2b274091250300209129930210",
		37,
		None,
		None,
		(DeviceInfoType.PULSE,) * 4,
		"energy-device-37-c",
	),
	captured_packet(
		"9019009c160a898a008804008a108800008a118800008a01888b00",
		0,
		100,
		True,
		(DeviceInfoType.POWER,) * 4,
		"central-unit-one-bus",
	),
	captured_packet(
		"901e009c1b0a838a008302008a108300008a118000008a018334008a02820000",
		0,
		100,
		True,
		(DeviceInfoType.POWER,) * 5,
		"central-unit-two-buses",
	),
	captured_packet(
		"9019009c164a818a008100008a108100008a118100008a01816600",
		0,
		100,
		True,
		(DeviceInfoType.POWER,) * 4,
		"central-unit-power-failure",
	),
	captured_packet(
		"900e089c0b0f85ae0000ee00004f00ce",
		8,
		None,
		None,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermometer-device-8",
	),
	captured_packet(
		"900e0b9c0b0f85ae0000d700004f00ce",
		11,
		None,
		None,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermometer-device-11",
	),
	captured_packet(
		"900e0a9c0b0f88ae0000c800004f00ce",
		10,
		None,
		None,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermometer-device-10",
	),
	captured_packet(
		"900b0a9c080a1cae0000020100",
		10,
		100,
		True,
		(DeviceInfoType.INPUT_VALUE,),
		"thermometer-device-10-input-value",
	),
	captured_packet(
		"900e099c0b0f86ae00009c00004f00ce",
		9,
		None,
		None,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermometer-device-9",
	),
	captured_packet(
		"900e0e9c0b0f86ae0000d500004f00ce",
		14,
		None,
		None,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermometer-device-14",
	),
	captured_packet(
		"900e179c0b0519ae0000a500004f00ce",
		23,
		50,
		True,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermostat-device-23-a",
	),
	captured_packet(
		"900e179c0b0519ae0000a400004f00ae",
		23,
		50,
		True,
		(DeviceInfoType.INPUT_VALUE, DeviceInfoType.INPUT_EXTENDED),
		"thermostat-device-23-b",
	),
	captured_packet("9005179c020519", 23, 50, True, (), "thermostat-device-23-without-temperature"),
	captured_packet(
		"900b189c080419ae00004a0000",
		24,
		40,
		True,
		(DeviceInfoType.INPUT_VALUE,),
		"thermostat-device-24",
	),
]


def parse_info_subpacket(packet: bytes) -> bytes:
	return Jablotron._parse_device_info_subpackets_from_device_info_packet(packet)[0][2:]


@pytest.mark.parametrize(
	(
		"packet_hex",
		"expected_device_number",
		"expected_battery_level",
		"expected_battery_ok",
		"expected_info_types",
	),
	CAPTURED_DEVICE_INFO_PACKETS,
)
def test_parse_captured_device_info_packet(
	packet_hex: str,
	expected_device_number: int,
	expected_battery_level: int | None,
	expected_battery_ok: bool | None,
	expected_info_types: tuple[DeviceInfoType, ...],
) -> None:
	packet = bytes.fromhex(packet_hex)

	assert len(packet) == packet[1] + 2
	assert Jablotron._is_device_info_packet(packet)
	assert Jablotron._parse_device_number_from_device_info_packet(packet) == expected_device_number

	subpackets = Jablotron._parse_device_info_subpackets_from_device_info_packet(packet)
	assert subpackets
	assert all(len(subpacket) == subpacket[1] + 2 for subpacket in subpackets)
	assert all(subpacket[:1] in DEVICE_INFO_KNOWN_SUBPACKETS for subpacket in subpackets)
	assert Jablotron._is_requested_device_info_packet(packet) == (subpackets[0][:1] == b"\x0a")

	info_subpacket = subpackets[0][2:]
	battery_state = Jablotron._parse_device_battery_level_from_device_info_packet(info_subpacket, packet)
	if expected_battery_level is None:
		assert battery_state is None
	else:
		assert battery_state is not None
		assert battery_state.level == expected_battery_level
		assert battery_state.ok == expected_battery_ok

	info_packets = Jablotron._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)
	assert tuple(info_packet.type for info_packet in info_packets) == expected_info_types


@pytest.mark.parametrize(
	("packet_hex", "device_number", "expected_temperature"),
	[
		pytest.param("900e089c0b0f85ae0000ee00004f00ce", 8, 23.8, id="device-8"),
		pytest.param("900e0b9c0b0f85ae0000d700004f00ce", 11, 21.5, id="device-11"),
		pytest.param("900e0a9c0b0f88ae0000c800004f00ce", 10, 20.0, id="device-10-a"),
		pytest.param("900b0a9c080a1cae0000020100", 10, 25.8, id="device-10-b"),
		pytest.param("900e099c0b0f86ae00009c00004f00ce", 9, 15.6, id="device-9"),
		pytest.param("900e0e9c0b0f86ae0000d500004f00ce", 14, 21.3, id="device-14"),
		pytest.param("900e179c0b0519ae0000a500004f00ce", 23, 16.5, id="device-23-a"),
		pytest.param("900e179c0b0519ae0000a400004f00ae", 23, 16.4, id="device-23-b"),
		pytest.param("900b189c080419ae00004a0000", 24, 7.4, id="device-24"),
	],
)
def test_parse_captured_input_value_temperature(
	packet_hex: str,
	device_number: int,
	expected_temperature: float,
) -> None:
	packet = bytes.fromhex(packet_hex)
	info_subpacket = parse_info_subpacket(packet)
	info_packets = Jablotron._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)
	input_value_packet = next(
		info_packet for info_packet in info_packets if info_packet.type == DeviceInfoType.INPUT_VALUE
	)
	jablotron = object.__new__(Jablotron)
	jablotron._update_entity_state = Mock()

	jablotron._parse_device_input_value(input_value_packet, device_number, packet)

	jablotron._update_entity_state.assert_called_once_with(
		"device_temperature_sensor_{}".format(device_number),
		expected_temperature,
	)


@pytest.mark.parametrize(
	("packet_hex", "device_number", "expected_temperature"),
	[
		pytest.param("900a140a070f87831a002521", 20, 26.0, id="device-20-a"),
		pytest.param("900a150a070f858319002521", 21, 25.0, id="device-21-a"),
		pytest.param("900a1b0a0708878315002421", 27, 21.0, id="device-27"),
		pytest.param("900a159c070f858317002821", 21, 23.0, id="device-21-b"),
		pytest.param("900a159c070f858316002821", 21, 22.0, id="device-21-c"),
		pytest.param("900a199c070f87831d001f2a", 25, 29.0, id="device-25"),
	],
)
def test_parse_captured_smoke_temperature(
	packet_hex: str,
	device_number: int,
	expected_temperature: float,
) -> None:
	packet = bytes.fromhex(packet_hex)
	jablotron = object.__new__(Jablotron)
	jablotron._update_entity_state = Mock()

	jablotron._parse_device_smoke_detector_info_packet(
		parse_info_subpacket(packet),
		device_number,
		packet,
	)

	jablotron._update_entity_state.assert_called_once_with(
		"device_temperature_sensor_{}".format(device_number),
		expected_temperature,
	)


def test_parse_captured_lan_info() -> None:
	packet = bytes.fromhex("900be90a080f00a683c0a844e3")
	jablotron = object.__new__(Jablotron)
	jablotron._add_lan_connection_ip = Mock()
	jablotron._update_entity_state = Mock()

	jablotron._parse_lan_connection_info_packet(parse_info_subpacket(packet), packet)

	assert jablotron._update_entity_state.call_args_list == [
		call("lan", "on"),
		call("lan_ip", "192.168.68.227"),
	]
	jablotron._add_lan_connection_ip.assert_called_once_with()


def test_parse_captured_gsm_info() -> None:
	packet = bytes.fromhex("900bea0a080f00a45023000001")
	jablotron = object.__new__(Jablotron)
	jablotron._update_entity_state = Mock()

	jablotron._parse_gsm_info_packet(parse_info_subpacket(packet), packet)

	assert jablotron._update_entity_state.call_args_list == [
		call("gsm_signal_sensor", "on"),
		call("gsm_signal_strength_sensor", 80.0),
	]


@pytest.mark.parametrize(
	("packet_hex", "device_number", "expected_standby_voltage", "expected_load_voltage"),
	[
		pytest.param(
			"900d049c0a0ae66c00a3016c018c01",
			4,
			41.9,
			39.6,
			id="power-precise-device-4",
		),
		pytest.param(
			"900d050a0a0a896c003f026c012f02",
			5,
			57.5,
			55.9,
			id="power-precise-device-5",
		),
		pytest.param(
			"900f1f0a0c0a868a003900008a01380000",
			31,
			5.7,
			5.6,
			id="power-device-31",
		),
	],
)
def test_parse_captured_siren_power(
	packet_hex: str,
	device_number: int,
	expected_standby_voltage: float,
	expected_load_voltage: float,
) -> None:
	packet = bytes.fromhex(packet_hex)
	jablotron = object.__new__(Jablotron)
	jablotron._update_entity_state = Mock()

	jablotron._parse_device_siren_info_packet(parse_info_subpacket(packet), device_number, packet)

	assert jablotron._update_entity_state.call_args_list == [
		call("battery_standby_voltage_{}".format(device_number), expected_standby_voltage),
		call("battery_load_voltage_{}".format(device_number), expected_load_voltage),
	]


def test_parse_captured_pulse_values() -> None:
	packet = bytes.fromhex(
		"9023249c200c3d906023274091ec06002091a8b50310906523274091ec06002091a8b50310"
	)
	jablotron = object.__new__(Jablotron)
	jablotron._add_pulse_to_electricity_meter = Mock()
	jablotron._update_entity_state = Mock()

	jablotron._parse_device_electricity_meter_with_pulse_info_packet(
		parse_info_subpacket(packet),
		36,
		packet,
	)

	assert jablotron._add_pulse_to_electricity_meter.call_args_list == [
		call(36, 0),
		call(36, 1),
	]
	assert jablotron._update_entity_state.call_args_list == [
		call("pulses_36", 1772),
		call("pulses_36_1", 46504),
	]


def test_input_extended_does_not_update_state() -> None:
	packet = bytes.fromhex("900e089c0b0f85ae0000ee00004f00ce")
	jablotron = object.__new__(Jablotron)
	jablotron._update_entity_state = Mock()

	jablotron._parse_device_input_value_info_packet(parse_info_subpacket(packet), 8, packet)

	jablotron._update_entity_state.assert_called_once_with("device_temperature_sensor_8", 23.8)
