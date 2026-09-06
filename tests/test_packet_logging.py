from __future__ import annotations

import logging
from unittest.mock import Mock

import pytest

from custom_components.jablotron100.const import (
	CONF_ENABLE_DEBUGGING,
	CONF_LOG_ALL_OUTCOMING_PACKETS,
	CONF_LOG_DEVICES_PACKETS,
	CONF_LOG_PG_OUTPUTS_PACKETS,
	CONF_LOG_SECTIONS_PACKETS,
	LOGGER,
	UI_CONTROL_AUTHORISATION_END,
	UI_CONTROL_TOGGLE_PG_OUTPUT,
)
from custom_components.jablotron100.jablotron import Jablotron


@pytest.mark.parametrize("code", ["4826", "48261973", "12*4826"])
@pytest.mark.parametrize("keepalive", [False, True])
def test_authorisation_logging_redacts_code_without_changing_sent_bytes(code, keepalive, caplog):
	jablotron = object.__new__(Jablotron)
	jablotron._options = {
		CONF_ENABLE_DEBUGGING: True,
		CONF_LOG_ALL_OUTCOMING_PACKETS: True,
	}
	jablotron._send_packet_by_stream = Mock()
	packets = (
		Jablotron.create_packets_keepalive(code)
		if keepalive else [Jablotron.create_packet_authorisation_code(code)]
	)

	with caplog.at_level(logging.DEBUG, logger=LOGGER.name):
		if keepalive:
			jablotron._send_packets(packets)
		else:
			jablotron._send_packet(packets[0])

	jablotron._send_packet_by_stream.assert_called_once_with(b"".join(packets))
	assert caplog.messages == [
		"Outcoming: authorisation code [redacted]",
		*["Outcoming: {}".format(packet.hex()) for packet in packets[1:]],
	]
	assert code not in caplog.text
	assert packets[0][3:].hex() not in caplog.text


@pytest.mark.parametrize("debugging,log_all", [(False, False), (False, True), (True, False)])
def test_authorisation_logging_respects_debug_options(debugging, log_all, caplog):
	jablotron = object.__new__(Jablotron)
	jablotron._options = {
		CONF_ENABLE_DEBUGGING: debugging,
		CONF_LOG_ALL_OUTCOMING_PACKETS: log_all,
		CONF_LOG_DEVICES_PACKETS: True,
		CONF_LOG_PG_OUTPUTS_PACKETS: True,
		CONF_LOG_SECTIONS_PACKETS: True,
	}
	with caplog.at_level(logging.DEBUG, logger=LOGGER.name):
		jablotron._log_outcoming_packet(Jablotron.create_packet_authorisation_code("4826"))
	assert caplog.messages == []


@pytest.mark.parametrize("packet", [
	Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
	Jablotron.create_packet_ui_control(UI_CONTROL_TOGGLE_PG_OUTPUT, b"\x03\x01"),
	b"",
	b"\x80",
	b"\x80\x08",
])
def test_non_authorisation_packets_keep_hex_logging(packet, caplog):
	jablotron = object.__new__(Jablotron)
	jablotron._options = {
		CONF_ENABLE_DEBUGGING: True,
		CONF_LOG_ALL_OUTCOMING_PACKETS: True,
	}
	with caplog.at_level(logging.DEBUG, logger=LOGGER.name):
		jablotron._log_outcoming_packet(packet)
	assert caplog.messages == ["Outcoming: {}".format(packet.hex())]