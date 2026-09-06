from __future__ import annotations

from unittest.mock import Mock, call

from homeassistant.const import STATE_OFF, STATE_ON
import pytest

from custom_components.jablotron100.const import CONF_NUMBER_OF_PG_OUTPUTS
from custom_components.jablotron100.jablotron import Jablotron


def create_jablotron(output_count):
	jablotron = object.__new__(Jablotron)
	jablotron._config = {CONF_NUMBER_OF_PG_OUTPUTS: output_count}
	jablotron._update_entity_state = Mock()
	return jablotron


@pytest.mark.parametrize("packet,output_count", [
	pytest.param(b"", 1, id="empty"),
	pytest.param(bytes.fromhex("50"), 1, id="missing-length"),
	pytest.param(bytes.fromhex("5000"), 1, id="empty-payload"),
	pytest.param(bytes.fromhex("5001"), 1, id="missing-payload"),
	pytest.param(bytes.fromhex("500200"), 1, id="truncated-declared-payload"),
	pytest.param(bytes.fromhex("500100"), 9, id="missing-output-bits"),
	pytest.param(bytes.fromhex("500100ff"), 9, id="trailing-data-not-in-payload"),
])
def test_incomplete_pg_packet_does_not_update_any_state(packet, output_count):
	jablotron = create_jablotron(output_count)
	jablotron._parse_pg_outputs_states_packet(packet)
	jablotron._update_entity_state.assert_not_called()


@pytest.mark.parametrize("packet,expected_states", [
	pytest.param(bytes.fromhex("500100"), [STATE_OFF], id="one-off"),
	pytest.param(bytes.fromhex("5001ff"), [STATE_ON] * 8, id="eight-on"),
	pytest.param(bytes.fromhex("50028101"), [STATE_ON] + [STATE_OFF] * 6 + [STATE_ON] * 2, id="cross-byte"),
	pytest.param(bytes.fromhex("500201ff"), [STATE_ON], id="extra-output-bits"),
])
def test_complete_pg_packet_updates_configured_outputs(packet, expected_states):
	jablotron = create_jablotron(len(expected_states))
	jablotron._parse_pg_outputs_states_packet(packet)
	assert jablotron._update_entity_state.call_args_list == [
		call(jablotron._get_pg_output_id(output_number), state)
		for output_number, state in enumerate(expected_states, start=1)
	]


def test_pg_packets_are_ignored_when_no_outputs_are_configured():
	jablotron = create_jablotron(0)
	jablotron._parse_pg_outputs_states_packet(b"")
	jablotron._update_entity_state.assert_not_called()