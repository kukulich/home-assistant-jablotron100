from __future__ import annotations

from collections import deque
from concurrent.futures import ThreadPoolExecutor
import sys
import threading
from unittest.mock import Mock

from homeassistant import core
from homeassistant.components.alarm_control_panel import AlarmControlPanelState
from homeassistant.const import CONF_PASSWORD
import pytest

from custom_components.jablotron100.const import UI_CONTROL_AUTHORISATION_END, UI_CONTROL_MODIFY_SECTION
from custom_components.jablotron100.errors import ServiceUnavailable
from custom_components.jablotron100.jablotron import Jablotron


@pytest.fixture
def authorisation(monkeypatch):
	jablotron = object.__new__(Jablotron)
	jablotron._config = {CONF_PASSWORD: "1234"}
	jablotron._authorisation_lock = threading.Lock()
	jablotron._login_failed = threading.Event()
	jablotron._authorisation_restore_pending = False
	jablotron._stream_stop_event = Mock()
	jablotron._stream_stop_event.is_set.return_value = False
	jablotron._stream_stop_event.wait.return_value = False
	jablotron._hass = Mock()
	callbacks = deque()
	jablotron._hass.loop.call_soon_threadsafe.side_effect = lambda callback, *args: callbacks.append((callback, args))
	jablotron._hass.async_add_executor_job.side_effect = lambda callback, *args: callback(*args)
	monkeypatch.setattr(core, "HassJob", lambda callback: callback, raising=False)
	monkeypatch.setattr(
		sys.modules[Jablotron.__module__], "async_call_later",
		lambda hass, delay, callback: callbacks.append((callback, (None,))),
	)
	packets = []
	jablotron._send_packet = Mock(side_effect=packets.append)
	jablotron._send_packets = Mock(side_effect=packets.extend)
	return jablotron, packets, callbacks


def test_later_request_cannot_reset_rejected_login(authorisation):
	jablotron, packets, callbacks = authorisation
	wrong_login = Jablotron.create_packet_authorisation_code("9876")

	def send_packets(batch):
		packets.extend(batch)
		if wrong_login in batch:
			jablotron._login_failed.set()

	jablotron._send_packets.side_effect = send_packets
	jablotron.modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "9876")
	jablotron.modify_alarm_control_panel_section_state(2, AlarmControlPanelState.ARMED_AWAY, None)
	while callbacks:
		callback, args = callbacks.popleft()
		callback(*args)

	assert Jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, b"\x90") not in packets
	assert Jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, b"\xa1") in packets


def test_temporary_login_is_restored_before_return(authorisation):
	jablotron, packets, callbacks = authorisation
	jablotron.modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "9876")
	assert packets[:3] == [
		Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
		Jablotron.create_packet_authorisation_code("9876"),
		Jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, b"\x90"),
	]
	assert packets[3:6] == [
		Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
		*Jablotron.create_packets_keepalive("1234"),
	]
	assert not callbacks
	assert not jablotron._authorisation_lock.locked()


def test_stopped_transaction_does_not_write(authorisation):
	jablotron, packets, callbacks = authorisation
	jablotron._stream_stop_event.is_set.return_value = True
	jablotron.modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "9876")
	assert packets == []
	assert not callbacks


@pytest.mark.parametrize("second_action", ["alarm", "pg"])
def test_competing_command_waits_until_temporary_login_is_restored(authorisation, second_action):
	jablotron, packets, callbacks = authorisation
	login_waiting = threading.Event()
	release_login = threading.Event()
	second_waiting = threading.Event()
	lock = threading.Lock()

	class ObservedLock:
		def __enter__(self):
			if lock.locked():
				second_waiting.set()
			lock.acquire()

		def __exit__(self, *args):
			lock.release()

	jablotron._authorisation_lock = ObservedLock()

	def wait_for_response(timeout):
		if not login_waiting.is_set():
			login_waiting.set()
			assert release_login.wait(5)
		return False

	jablotron._stream_stop_event.wait.side_effect = wait_for_response
	with ThreadPoolExecutor(max_workers=2) as executor:
		first = executor.submit(jablotron.modify_alarm_control_panel_section_state, 1, AlarmControlPanelState.DISARMED, "9876")
		try:
			assert login_waiting.wait(5)
			if second_action == "alarm":
				second = executor.submit(jablotron.modify_alarm_control_panel_section_state, 2, AlarmControlPanelState.ARMED_AWAY, None)
			else:
				second = executor.submit(jablotron.toggle_pg_output, 1, "on")
			assert second_waiting.wait(5)
			assert packets == [
				Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
				Jablotron.create_packet_authorisation_code("9876"),
			]
		finally:
			release_login.set()
		first.result(timeout=5)
		second.result(timeout=5)
	assert packets[3:6] == [
		Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
		*Jablotron.create_packets_keepalive("1234"),
	]
	assert len(packets) > 7
	assert not callbacks


def test_keepalive_skips_busy_transaction_without_resetting_failure(authorisation):
	jablotron, packets, callbacks = authorisation
	jablotron._login_failed.set()
	with jablotron._authorisation_lock:
		assert not jablotron._send_keepalive()
	assert packets == []
	assert jablotron._login_failed.is_set()
	assert jablotron._send_keepalive()
	assert packets == Jablotron.create_packets_keepalive("1234")
	assert jablotron._login_failed.is_set()


@pytest.mark.parametrize("failure_stage", ["login", "modify", "restore"])
def test_io_failure_releases_lock_and_attempts_restore(authorisation, failure_stage):
	jablotron, packets, callbacks = authorisation
	login = Jablotron.create_packet_authorisation_code("9876")
	restore = Jablotron.create_packet_authorisation_code("1234")
	modify = Jablotron.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, b"\x90")
	failed_packet = {"login": login, "modify": modify, "restore": restore}[failure_stage]

	def send_packets(batch):
		packets.extend(batch)
		if failed_packet in batch:
			raise OSError("Synthetic write failure")

	jablotron._send_packets.side_effect = send_packets
	jablotron._send_packet.side_effect = lambda packet: send_packets([packet])
	with pytest.raises(OSError, match="Synthetic write failure"):
		jablotron.modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "9876")
	assert restore in packets
	assert not jablotron._authorisation_lock.locked()
	assert not callbacks
	if failure_stage == "restore":
		assert jablotron._authorisation_restore_pending
		with pytest.raises(ServiceUnavailable):
			jablotron.toggle_pg_output(1, "on")
		jablotron._send_packets.side_effect = packets.extend
		assert jablotron._send_keepalive()
		assert packets[-3:] == [
			Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
			*Jablotron.create_packets_keepalive("1234"),
		]
		assert not jablotron._authorisation_restore_pending


def test_shutdown_during_login_wait_prevents_modify_and_restore(authorisation):
	jablotron, packets, callbacks = authorisation

	def stop_during_wait(timeout):
		jablotron._stream_stop_event.is_set.return_value = True
		return True

	jablotron._stream_stop_event.wait.side_effect = stop_during_wait
	jablotron.modify_alarm_control_panel_section_state(1, AlarmControlPanelState.DISARMED, "9876")
	assert len(packets) == 2
	assert not jablotron._authorisation_lock.locked()
	assert not callbacks