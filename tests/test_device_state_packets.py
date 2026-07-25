from __future__ import annotations

from unittest.mock import Mock, call

import pytest

from custom_components.jablotron100.const import (
	CONF_DEVICES,
	CONF_NUMBER_OF_DEVICES,
	DeviceConnection,
	DeviceData,
	DeviceFault,
	DeviceType,
	PACKET_DEVICE_STATE,
	SIGNAL_STRENGTH_STEP,
)
from custom_components.jablotron100.jablotron import Jablotron, JablotronCentralUnit


ACTIVITY = "activity"
HEARTBEAT = "heartbeat"


def captured_packet(
	packet: str,
	device_number: int,
	state: str,
	packet_info: str | DeviceFault,
	signal_strength: int | None,
	packet_id: str,
):
	return pytest.param(
		packet,
		device_number,
		state,
		packet_info,
		signal_strength,
		id=packet_id,
	)


CAPTURED_DEVICE_STATE_PACKETS = [
	# Activity packets captured while an alarm was active.
	captured_packet("550900c90006b1cdf21c06", 24, "on", ACTIVITY, 30, "alarm-activity-device-24"),
	captured_packet("5509a8d18006118f710a10", 26, "on", ACTIVITY, 80, "alarm-activity-device-26-a"),
	captured_packet("5509a8d5c0069190910a0d", 27, "on", ACTIVITY, 65, "alarm-activity-device-27"),
	captured_packet("5509a8d900078191d10a0e", 28, "on", ACTIVITY, 70, "alarm-activity-device-28"),
	captured_packet("5509a8d18006b198314b10", 26, "on", ACTIVITY, 80, "alarm-activity-device-26-b"),
	captured_packet("5509a8dd40072182910814", 29, "on", ACTIVITY, 100, "alarm-activity-device-29"),
	captured_packet("5509a8e180078181710814", 30, "on", ACTIVITY, 100, "alarm-activity-device-30"),

	captured_packet("5508456c400000000000", 1, "on", DeviceFault.POWER_SUPPLY, None, "power-supply-fault-0x45"),
	captured_packet("5508076c400000000000", 1, "on", DeviceFault.UNKNOWN, None, "device-fault-0x07"),
	captured_packet("5508346c400000000000", 1, "on", DeviceFault.BATTERY, None, "battery-fault-0x34"),
	captured_packet("5508866c400000000000", 1, "on", DeviceFault.SABOTAGE, None, "sabotage-fault-0x86"),
	captured_packet("5508066c400000000000", 1, "on", DeviceFault.SABOTAGE, None, "sabotage-fault-0x06"),

	# Backup battery failure and recovery in the central unit.
	captured_packet("550834680000a0c3b518", 0, "on", DeviceFault.BATTERY, None, "central-battery-failure-a"),
	captured_packet("5508346a000020a50805", 0, "off", DeviceFault.BATTERY, None, "central-battery-recovery-a"),
	captured_packet("5508346a0000b0969490", 0, "off", DeviceFault.BATTERY, None, "central-battery-recovery-b"),
	captured_packet("550834680000b003b32a", 0, "on", DeviceFault.BATTERY, None, "central-battery-failure-b"),

	# Battery fault recovery reported by a peripheral.
	captured_packet("550934ca0006b134f1060a", 24, "off", DeviceFault.BATTERY, 50, "peripheral-battery-recovery"),

	# Heartbeat/periodic status packets from a radio module.
	captured_packet("550833c0800540208a0d", 22, "on", HEARTBEAT, None, "radio-module-heartbeat-a"),
	captured_packet("550833c080054020aa0d", 22, "on", HEARTBEAT, None, "radio-module-heartbeat-b"),
	captured_packet("550833c08005d0ad501b", 22, "on", HEARTBEAT, None, "radio-module-heartbeat-c"),
	captured_packet("550833c08005d0ad705b", 22, "on", HEARTBEAT, None, "radio-module-heartbeat-d"),
	captured_packet("550833c08005d03c4c3e", 22, "on", HEARTBEAT, None, "radio-module-heartbeat-e"),
	captured_packet("550833c08005d03c6c3e", 22, "on", HEARTBEAT, None, "radio-module-heartbeat-f"),

	# Siren heartbeat packets using both observed heartbeat information values.
	captured_packet("5508337c4001a19f4e0a", 5, "on", HEARTBEAT, None, "siren-heartbeat-0x33"),
	captured_packet("55084fcc400660a90310", 25, "on", HEARTBEAT, None, "siren-heartbeat-a"),
	captured_packet("55084f7c40010028e724", 5, "on", HEARTBEAT, None, "siren-heartbeat-b"),
	captured_packet("55084f7c4f0100111115", 5, "on", HEARTBEAT, None, "siren-heartbeat-reconstructed"),

	# Heartbeat/periodic status packet from a CO detector.
	captured_packet("55093308010ac5b6500b0d", 40, "on", HEARTBEAT, 65, "co-detector-heartbeat"),

	# LAN connection failure and recovery packets used by different central units.
	captured_packet("5508075c421fb0581525", 125, "on", DeviceFault.UNKNOWN, None, "lan-failure-device-125-a"),
	captured_packet("5508075e421f90633525", 125, "off", DeviceFault.UNKNOWN, None, "lan-recovery-device-125-a"),
	captured_packet("5508075c421fb08b8b3d", 125, "on", DeviceFault.UNKNOWN, None, "lan-failure-device-125-b"),
	captured_packet("5508075c421f7019d512", 125, "on", DeviceFault.UNKNOWN, None, "lan-failure-device-125-c"),
	captured_packet("5508070c443ab08bb2be", 233, "on", DeviceFault.UNKNOWN, None, "lan-failure-device-233"),
	captured_packet("5508070e443ae028d62e", 233, "off", DeviceFault.UNKNOWN, None, "lan-recovery-device-233-a"),
	captured_packet("5508070e443a50ac1010", 233, "off", DeviceFault.UNKNOWN, None, "lan-recovery-device-233-b"),

	# External power loss and restoration.
	captured_packet("550945780001408ff61604", 4, "on", DeviceFault.POWER_SUPPLY, 20, "power-supply-failure"),
	captured_packet("5509457a00015090161704", 4, "off", DeviceFault.POWER_SUPPLY, 20, "power-supply-recovery"),

	# Activity packets from ordinary wired devices. Bytes after the device number
	# vary, but do not change the decoded device number or active state.
	captured_packet("5508ae6d4200810f3501", 1, "on", ACTIVITY, None, "wired-activity-device-1-a"),
	captured_packet("5508ae6d4200615f0c09", 1, "on", ACTIVITY, None, "wired-activity-device-1-b"),
	captured_packet("55080c6d4200915f2c09", 1, "on", ACTIVITY, None, "wired-activity-device-1-c"),
	captured_packet("55080171800020401123", 2, "on", ACTIVITY, None, "wired-activity-device-2-a"),
	captured_packet("550801718000f0415123", 2, "on", ACTIVITY, None, "wired-activity-device-2-b"),
	captured_packet("550801718000c0665128", 2, "on", ACTIVITY, None, "wired-activity-device-2-c"),
	captured_packet("550801718000e0799129", 2, "on", ACTIVITY, None, "wired-activity-device-2-d"),
	captured_packet("55080179000150787129", 4, "on", ACTIVITY, None, "wired-activity-device-4-a"),
	captured_packet("550801790001a0805438", 4, "on", ACTIVITY, None, "wired-activity-device-4-b"),
	captured_packet("5508018180013059ec06", 6, "on", ACTIVITY, None, "wired-activity-device-6"),
	captured_packet("550881890002105bcc07", 8, "on", ACTIVITY, None, "wired-activity-device-8-a"),
	captured_packet("550881890002405bec07", 8, "on", ACTIVITY, None, "wired-activity-device-8-b"),
	captured_packet("5508819180022055f125", 10, "on", ACTIVITY, None, "wired-activity-device-10-a"),
	captured_packet("550881918002a0581127", 10, "on", ACTIVITY, None, "wired-activity-device-10-b"),
	captured_packet("550881918002f0567126", 10, "on", ACTIVITY, None, "wired-activity-device-10-c"),
	captured_packet("55088199000390479124", 12, "on", ACTIVITY, None, "wired-activity-device-12-a"),
	captured_packet("5508819900036095701c", 12, "on", ACTIVITY, None, "wired-activity-device-12-b"),
	captured_packet("550881990003805b7127", 12, "on", ACTIVITY, None, "wired-activity-device-12-c"),
	captured_packet("550881990003f080312a", 12, "on", ACTIVITY, None, "wired-activity-device-12-d"),
	captured_packet("55088199000380b6912b", 12, "on", ACTIVITY, None, "wired-activity-device-12-e"),
	captured_packet("550881a1800370463124", 14, "on", ACTIVITY, None, "wired-activity-device-14"),
	captured_packet("550881a9000420b21439", 16, "on", ACTIVITY, None, "wired-activity-device-16-a"),
	captured_packet("550881a9000490b8b43a", 16, "on", ACTIVITY, None, "wired-activity-device-16-b"),
	captured_packet("550881b180044084122d", 18, "on", ACTIVITY, None, "wired-activity-device-18-a"),
	captured_packet("550881b18004104ef124", 18, "on", ACTIVITY, None, "wired-activity-device-18-b"),
	captured_packet("550881b18004d061f127", 18, "on", ACTIVITY, None, "wired-activity-device-18-c"),
	captured_packet("550881b18004207df129", 18, "on", ACTIVITY, None, "wired-activity-device-18-d"),
	captured_packet("550881b18004a04f7125", 18, "on", ACTIVITY, None, "wired-activity-device-18-e"),
	captured_packet("550881b180049050932e", 18, "on", ACTIVITY, None, "wired-activity-device-18-f"),

	# End of an unspecified peripheral fault.
	captured_packet("550907ca0006318ce03006", 24, "off", DeviceFault.UNKNOWN, 30, "peripheral-fault-recovery"),

	# Activity packets from wireless perimeter devices.
	captured_packet("5509a3d18006f17cd12911", 26, "on", ACTIVITY, 85, "wireless-activity-device-26-a"),
	captured_packet("5509a3d1800691606c090f", 26, "on", ACTIVITY, 75, "wireless-activity-device-26-b"),
	captured_packet("550981d5c006b1618c090b", 27, "on", ACTIVITY, 55, "wireless-activity-device-27-a"),
	captured_packet("550981d5c0064162ac0907", 27, "on", ACTIVITY, 35, "wireless-activity-device-27-b"),
	captured_packet("550981d900079150b32e08", 28, "on", ACTIVITY, 40, "wireless-activity-device-28-a"),
	captured_packet("550981d900075162cc090a", 28, "on", ACTIVITY, 50, "wireless-activity-device-28-b"),
	captured_packet("550981dd4007e162ec0912", 29, "on", ACTIVITY, 90, "wireless-activity-device-29"),
	captured_packet("550981e1800791630c0a0a", 30, "on", ACTIVITY, 50, "wireless-activity-device-30-a"),
	captured_packet("550981e18007314a8b0c14", 30, "on", ACTIVITY, 100, "wireless-activity-device-30-b"),
	captured_packet("550981e1800741520b0d14", 30, "on", ACTIVITY, 100, "wireless-activity-device-30-c"),

	# Sabotage/tamper activation and recovery.
	captured_packet("550986e08007e15deb0d13", 30, "on", DeviceFault.SABOTAGE, 95, "sabotage-activation-a"),
	captured_packet("550986e080070170cf3f0e", 30, "on", DeviceFault.SABOTAGE, 70, "sabotage-activation-b"),
	captured_packet("550986e2800731700f0013", 30, "off", DeviceFault.SABOTAGE, 95, "sabotage-recovery"),
]


def create_device_state_packet(
	device_number: int,
	*,
	active: bool = True,
	state_info: int = 0,
	signal_strength: int = 0,
) -> bytes:
	packet = bytearray(11)
	packet[0:1] = PACKET_DEVICE_STATE
	packet[1] = 9
	packet[2] = state_info
	packet[3] = _device_state_value(device_number, active)
	packet[4:6] = (device_number << 6).to_bytes(2, byteorder="little")
	packet[10] = signal_strength
	return bytes(packet)


def _device_state_value(device_number: int, active: bool) -> int:
	if device_number <= 37:
		normalized_device_number = device_number
	elif device_number <= 101:
		normalized_device_number = device_number - 64
	elif device_number <= 165:
		normalized_device_number = device_number - 128
	elif device_number <= 229:
		normalized_device_number = device_number - 192
	else:
		normalized_device_number = device_number - 256

	return normalized_device_number * 4 + 104 + (0 if active else 2)


def create_jablotron(
	device_number: int,
	*,
	connection: DeviceConnection = DeviceConnection.WIRED,
	has_battery: bool = False,
	device_type: DeviceType = DeviceType.MOTION_DETECTOR,
) -> Jablotron:
	jablotron = object.__new__(Jablotron)
	jablotron._central_unit = JablotronCentralUnit("test", "UNKNOWN", "1", "1")
	jablotron._config = {
		CONF_NUMBER_OF_DEVICES: 230,
		CONF_DEVICES: [device_type.value] * 230,
	}
	jablotron._devices_data = {
		jablotron._get_device_id(device_number): {
			DeviceData.BATTERY: has_battery,
			DeviceData.CONNECTION: connection,
		},
	}
	jablotron._update_entity_state = Mock()
	return jablotron


@pytest.mark.parametrize(
	("packet_hex", "expected_device_number", "expected_state", "expected_packet_info", "expected_signal_strength"),
	CAPTURED_DEVICE_STATE_PACKETS,
)
def test_parse_captured_device_state_packet(
	packet_hex: str,
	expected_device_number: int,
	expected_state: str,
	expected_packet_info: str | DeviceFault,
	expected_signal_strength: int | None,
) -> None:
	packet = bytes.fromhex(packet_hex)

	assert len(packet) == packet[1] + 2
	assert Jablotron._is_device_state_packet(packet)
	assert Jablotron._parse_device_number_from_device_state_packet(packet) == expected_device_number
	assert Jablotron._convert_jablotron_device_state_to_state(packet, expected_device_number) == expected_state

	fault = Jablotron._parse_device_fault_from_device_state_packet(packet)
	is_heartbeat = Jablotron._is_heartbeat_device_state_packet(packet)

	if isinstance(expected_packet_info, DeviceFault):
		assert fault == expected_packet_info
	elif expected_packet_info == HEARTBEAT:
		assert is_heartbeat
		assert fault is None
	else:
		assert fault is None
		assert not is_heartbeat

	if expected_signal_strength is None:
		assert len(packet) == 10
	else:
		assert Jablotron.bytes_to_int(packet[10:11]) * SIGNAL_STRENGTH_STEP == expected_signal_strength


@pytest.mark.parametrize("device_number", [0, 1, 37, 38, 101, 102, 165, 166, 229, 230, 251, 254])
def test_parse_device_number(device_number: int) -> None:
	packet = create_device_state_packet(device_number)

	assert Jablotron._parse_device_number_from_device_state_packet(packet) == device_number


@pytest.mark.parametrize("device_number", [1, 37, 38, 101, 102, 165, 166, 229, 230])
@pytest.mark.parametrize(("active", "expected_state"), [(True, "on"), (False, "off")])
def test_convert_device_state(device_number: int, active: bool, expected_state: str) -> None:
	packet = create_device_state_packet(device_number, active=active)

	assert Jablotron._convert_jablotron_device_state_to_state(packet, device_number) == expected_state


def test_convert_unknown_device_state() -> None:
	packet = bytearray(create_device_state_packet(1))
	packet[3] = 0

	assert Jablotron._convert_jablotron_device_state_to_state(bytes(packet), 1) is None


def test_parse_device_state_updates_state_and_wireless_signal_strength() -> None:
	device_number = 166
	jablotron = create_jablotron(device_number, connection=DeviceConnection.WIRELESS)
	packet = create_device_state_packet(device_number, signal_strength=7)

	jablotron._parse_device_state_packet(packet)

	assert jablotron._update_entity_state.call_args_list == [
		call("device_sensor_166", "on", store_state=False),
		call("device_signal_strength_sensor_166", 7 * SIGNAL_STRENGTH_STEP),
	]


def test_parse_heartbeat_only_updates_wireless_signal_strength() -> None:
	device_number = 1
	jablotron = create_jablotron(device_number, connection=DeviceConnection.WIRELESS)
	packet = create_device_state_packet(device_number, state_info=0x0F, signal_strength=4)

	jablotron._parse_device_state_packet(packet)

	jablotron._update_entity_state.assert_called_once_with(
		"device_signal_strength_sensor_1",
		4 * SIGNAL_STRENGTH_STEP,
	)


def test_parse_radio_module_0x33_packet_as_heartbeat() -> None:
	jablotron = create_jablotron(22, device_type=DeviceType.RADIO_MODULE)

	jablotron._parse_device_state_packet(bytes.fromhex("550833c0800540208a0d"))

	jablotron._update_entity_state.assert_not_called()


def test_parse_co_detector_0x33_packet_as_heartbeat() -> None:
	jablotron = create_jablotron(
		40,
		connection=DeviceConnection.WIRELESS,
		has_battery=True,
		device_type=DeviceType.GAS_DETECTOR,
	)

	jablotron._parse_device_state_packet(bytes.fromhex("55093308010ac5b6500b0d"))

	jablotron._update_entity_state.assert_called_once_with(
		"device_signal_strength_sensor_40",
		65,
	)


def test_parse_battery_fault_updates_battery_problem() -> None:
	device_number = 1
	jablotron = create_jablotron(device_number, has_battery=True)
	packet = create_device_state_packet(device_number, state_info=0x04)

	jablotron._parse_device_state_packet(packet)

	jablotron._update_entity_state.assert_called_once_with(
		"device_battery_problem_sensor_1",
		"on",
	)


def test_parse_battery_fault_is_device_state_without_battery() -> None:
	device_number = 1
	jablotron = create_jablotron(device_number)
	packet = create_device_state_packet(device_number, state_info=0x04)

	jablotron._parse_device_state_packet(packet)

	jablotron._update_entity_state.assert_called_once_with(
		"device_sensor_1",
		"on",
		store_state=False,
	)


def test_parse_non_battery_fault_updates_device_problem() -> None:
	device_number = 1
	jablotron = create_jablotron(device_number)
	packet = create_device_state_packet(device_number, state_info=0x06)

	jablotron._parse_device_state_packet(packet)

	jablotron._update_entity_state.assert_called_once_with(
		"device_problem_sensor_1",
		"on",
	)
