from __future__ import annotations

import threading
from unittest.mock import Mock, patch

from homeassistant.components.alarm_control_panel import AlarmControlPanelState
import pytest
import voluptuous as vol

from custom_components.jablotron100.alarm_control_panel import JablotronAlarmControlPanelEntity
from custom_components.jablotron100.const import EVENT_WRONG_CODE, UI_CONTROL_MODIFY_SECTION
from custom_components.jablotron100.jablotron import JablotronAlarmControlPanel


pytestmark = pytest.mark.asyncio


async def test_alarm_service_runs_complete_transaction_off_event_loop(hass, jablotron, entity_component):
	control = JablotronAlarmControlPanel(jablotron.central_unit(), None, "section_1", 1)
	jablotron.entities_states[control.id] = AlarmControlPanelState.ARMED_AWAY
	entity = JablotronAlarmControlPanelEntity(jablotron, control)
	entity.entity_id = "alarm_control_panel.jablotron_authorisation"
	component = entity_component("alarm_control_panel")
	component.async_register_entity_service("alarm_disarm", {vol.Optional("code"): str}, "async_alarm_disarm")
	loop_thread = threading.get_ident()
	packets = []

	def wait_for_response(timeout):
		assert threading.get_ident() != loop_thread
		assert jablotron._authorisation_lock.locked()
		return False

	try:
		await component.async_add_entities([entity])
		with (
			patch.object(jablotron._stream_stop_event, "wait", side_effect=wait_for_response) as wait,
			patch.object(jablotron, "_send_packets", side_effect=packets.extend),
			patch.object(jablotron, "_send_packet", side_effect=packets.append),
		):
			await hass.services.async_call(
				"alarm_control_panel", "alarm_disarm",
				{"entity_id": entity.entity_id, "code": "9876"}, blocking=True,
			)
		assert wait.call_count == 2
		assert jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, b"\x90") in packets
		assert jablotron.create_packet_authorisation_code("1234") in packets
		assert not jablotron._authorisation_lock.locked()
		assert not jablotron._authorisation_restore_pending
	finally:
		await entity.async_remove()


async def test_reader_marks_failed_login_and_preserves_wrong_code_event(hass, jablotron):
	events = []
	unsubscribe = hass.bus.async_listen(EVENT_WRONG_CODE, events.append)
	stream = Mock()
	jablotron._last_authorized_user_or_device = "User 1"

	def read_packet(size):
		jablotron._stream_stop_event.set()
		return bytes.fromhex("80021b03")

	stream.read.side_effect = read_packet
	try:
		with (
			patch.object(jablotron, "_open_read_stream", return_value=stream),
			patch("custom_components.jablotron100.jablotron.time.sleep"),
		):
			await hass.async_add_executor_job(jablotron._read_packets)
		await hass.async_block_till_done()
		assert jablotron._login_failed.is_set()
		assert jablotron._last_authorized_user_or_device is None
		assert len(events) == 1
		stream.close.assert_called_once_with()
	finally:
		unsubscribe()


@pytest.mark.parametrize("read_error", [False, True])
async def test_reader_disconnect_marks_pending_login_failed(hass, jablotron, read_error):
	stream = Mock()

	def read_packet(size):
		jablotron._stream_stop_event.set()
		if read_error:
			raise OSError("Synthetic read failure")
		return b""

	stream.read.side_effect = read_packet
	with (
		patch.object(jablotron, "_open_read_stream", return_value=stream),
		patch.object(jablotron, "_redetect_serial_port"),
		patch("custom_components.jablotron100.jablotron.time.sleep"),
	):
		await hass.async_add_executor_job(jablotron._read_packets)
	assert jablotron._login_failed.is_set()
	assert not jablotron.last_update_success
	stream.close.assert_called_once_with()