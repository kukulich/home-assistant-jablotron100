from __future__ import annotations

from unittest.mock import Mock

from homeassistant.components.alarm_control_panel import AlarmControlPanelState
from homeassistant.const import CONF_PASSWORD
import pytest

from custom_components.jablotron100.jablotron import Jablotron


@pytest.mark.parametrize("code", [
	"", "123", "123456789", "1234567890", "abcd", "123x", "1234abcd",
	" 1234", "1234 ", "+1234", "12\n34", "\u0661\u0662\u0663\u0664",
	"*1234", "12*", "1**1234", "1234*1234", "1*123", "1*1234567",
])
def test_invalid_authorisation_code_is_rejected_without_exposing_code(code):
	with pytest.raises(ValueError, match="^Invalid authorisation code$"):
		Jablotron.create_packet_authorisation_code(code)


@pytest.mark.parametrize("code,expected", [
	("1234", "80080339393931323334"),
	("12345", "80080339393951323334"),
	("123456", "80080339393951623334"),
	("1234567", "80080339393951627334"),
	("12345678", "80080339393951627384"),
	("12*3456", "80080330313233343536"),
	("1*345678", "80080331333435363738"),
	("123*345678", "800a03313233333435363738"),
])
def test_valid_authorisation_code_keeps_wire_encoding(code, expected):
	assert Jablotron.create_packet_authorisation_code(code) == bytes.fromhex(expected)


@pytest.mark.parametrize("code", ["abc4", "123456789", "1**1234"])
def test_invalid_service_code_reports_wrong_code_without_sending_packets(code):
	jablotron = object.__new__(Jablotron)
	jablotron._config = {CONF_PASSWORD: "1234"}
	jablotron._hass = Mock()
	jablotron._login_error = Mock()
	jablotron._send_packet = Mock()
	jablotron._send_packets = Mock()
	jablotron.modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, code)
	jablotron._login_error.assert_called_once_with()
	jablotron._send_packet.assert_not_called()
	jablotron._send_packets.assert_not_called()
	jablotron._hass.loop.call_soon_threadsafe.assert_not_called()