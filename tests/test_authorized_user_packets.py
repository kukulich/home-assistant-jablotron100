from __future__ import annotations

import pytest

from custom_components.jablotron100.jablotron import Jablotron, JablotronCentralUnit


def captured_user_packet(
	packet: str,
	device_number: int,
	expected_user_or_device: str,
	packet_id: str,
):
	return pytest.param(
		packet,
		device_number,
		expected_user_or_device,
		id=packet_id,
	)


JA_107_CAPTURED_PACKETS = [
	captured_user_packet("55080c2d8400a159f33a", 2, "User 0", "keypad-2-user-0-disarm"),
	captured_user_packet("55082e2d8400c15a133b", 2, "User 0", "keypad-2-user-0-arm"),
	captured_user_packet("55080c318400515c533b", 2, "User 1", "keypad-2-user-1-disarm"),
	captured_user_packet("55082e318400e15c733b", 2, "User 1", "keypad-2-user-1-arm"),
	captured_user_packet("55080c358400415eb33b", 2, "User 2", "keypad-2-user-2-disarm"),
	captured_user_packet("55082e358400415fd33b", 2, "User 2", "keypad-2-user-2-arm"),
	captured_user_packet("55080c398400d160f33b", 2, "User 3", "keypad-2-user-3-disarm"),
	captured_user_packet("55082e398400b161133c", 2, "User 3", "keypad-2-user-3-arm"),
	captured_user_packet("55080c3d84000163333c", 2, "User 4", "keypad-2-user-4-disarm"),
	captured_user_packet("55082e3d84001164733c", 2, "User 4", "keypad-2-user-4-arm"),
	captured_user_packet("55080c4184009165b33c", 2, "User 5", "keypad-2-user-5-disarm"),
	captured_user_packet("55082e4184004166f33c", 2, "User 5", "keypad-2-user-5-arm"),
	captured_user_packet("55080c2d040131878912", 4, "User 0", "keypad-4-user-0-disarm"),
	captured_user_packet("55082e2d04013188a912", 4, "User 0", "keypad-4-user-0-arm"),
	captured_user_packet("55080c310401d189e912", 4, "User 1", "keypad-4-user-1-disarm"),
	captured_user_packet("55082e310401918a0913", 4, "User 1", "keypad-4-user-1-arm"),
	captured_user_packet("55080c350401318c6913", 4, "User 2", "keypad-4-user-2-disarm"),
	captured_user_packet("55082e350401218da913", 4, "User 2", "keypad-4-user-2-arm"),
	captured_user_packet("55080c390401a18ee913", 4, "User 3", "keypad-4-user-3-disarm"),
	captured_user_packet("55082e39040141902914", 4, "User 3", "keypad-4-user-3-arm"),
	captured_user_packet("55080c3d040171928914", 4, "User 4", "keypad-4-user-4-disarm"),
	captured_user_packet("55082e3d04010193a914", 4, "User 4", "keypad-4-user-4-arm"),
	captured_user_packet("55080c410401d194c914", 4, "User 5", "keypad-4-user-5-disarm"),
	captured_user_packet("55082e4104017195e914", 4, "User 5", "keypad-4-user-5-arm"),
	captured_user_packet("55090c2d440371d9c9160e", 13, "User 0", "keypad-13-user-0-disarm"),
	captured_user_packet("55092e2d440331db09170d", 13, "User 0", "keypad-13-user-0-arm"),
	captured_user_packet("55090c31440381dd49170d", 13, "User 1", "keypad-13-user-1-disarm"),
	captured_user_packet("55092e31440331de69170e", 13, "User 1", "keypad-13-user-1-arm"),
	captured_user_packet("55090c354403a1df89170e", 13, "User 2", "keypad-13-user-2-disarm"),
	captured_user_packet("55092e354403c1e0a9170e", 13, "User 2", "keypad-13-user-2-arm"),
	captured_user_packet("55090c39440351e2c91708", 13, "User 3", "keypad-13-user-3-disarm"),
	captured_user_packet("55092e394403f1e2e9170d", 13, "User 3", "keypad-13-user-3-arm"),
	captured_user_packet("55090c3d440391e509180d", 13, "User 4", "keypad-13-user-4-disarm"),
	captured_user_packet("55092e3d440321e629180e", 13, "User 4", "keypad-13-user-4-arm"),
	captured_user_packet("55090c414403a1e749180d", 13, "User 5", "keypad-13-user-5-disarm"),
	captured_user_packet("55092e41440391e969180e", 13, "User 5", "keypad-13-user-5-arm"),
	captured_user_packet("55080c40843f9168133d", 254, "User 5", "usb-user-5-disarm"),
	captured_user_packet("55080b40843ff1024a19", 254, "User 5", "usb-user-5-arm"),
	captured_user_packet("55082e718000c169333d", 2, "Device 2", "keypad-2-no-authorization"),
	captured_user_packet("55082e79000171996915", 4, "Device 4", "keypad-4-no-authorization"),
	captured_user_packet("55092e9d400321eea9180e", 13, "Device 13", "keypad-13-no-authorization"),
]


JA_101_CAPTURED_PACKETS = [
	captured_user_packet("5508ae6c823ec1842d3c", 251, "User 1", "mobile-app-user-1-arm-partially"),
	captured_user_packet("55080c6c823e81854d3c", 251, "User 1", "mobile-app-user-1-disarm"),
	captured_user_packet("5508ae70823e019ccd3e", 251, "User 2", "mobile-app-user-2-arm-partially"),
	captured_user_packet("55080c70823eb19ced3e", 251, "User 2", "mobile-app-user-2-disarm"),
	captured_user_packet("55082e6c823e21ec2d08", 251, "User 1", "mobile-app-user-1-arm"),
	captured_user_packet("55088b74823f7015d609", 254, "User 3", "usb-user-3-arm-pending"),
	captured_user_packet("55080c74823f4016f609", 254, "User 3", "usb-user-3-disarm"),
]


def create_jablotron(model: str) -> Jablotron:
	jablotron = object.__new__(Jablotron)
	jablotron._central_unit = JablotronCentralUnit("test", model, "1", "1")
	jablotron._last_authorized_user_or_device = None
	return jablotron


@pytest.mark.parametrize(
	("packet_hex", "device_number", "expected_user_or_device"),
	JA_107_CAPTURED_PACKETS,
)
def test_detect_authorized_user_or_device_from_ja_107_packet(
	packet_hex: str,
	device_number: int,
	expected_user_or_device: str,
) -> None:
	jablotron = create_jablotron("JA-107K")

	jablotron._set_last_authorized_user_or_device_from_device_state_packet(
		bytes.fromhex(packet_hex),
		device_number,
	)

	assert jablotron.last_authorized_user_or_device() == expected_user_or_device


@pytest.mark.parametrize(
	("packet_hex", "device_number", "expected_user_or_device"),
	JA_101_CAPTURED_PACKETS,
)
def test_detect_authorized_user_from_ja_101_system_device_packet(
	packet_hex: str,
	device_number: int,
	expected_user_or_device: str,
) -> None:
	jablotron = create_jablotron("JA-101K")

	jablotron._set_last_authorized_user_or_device_from_device_state_packet(
		bytes.fromhex(packet_hex),
		device_number,
	)

	assert jablotron.last_authorized_user_or_device() == expected_user_or_device
