from __future__ import annotations

import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

from homeassistant.const import CONF_PASSWORD
from homeassistant.data_entry_flow import FlowResultType
import pytest

from custom_components.jablotron100 import PLATFORMS, async_unload_entry
from custom_components.jablotron100.config_flow import JablotronConfigFlow
from custom_components.jablotron100.const import (
	AUTODETECT_SERIAL_PORT,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_SERIAL_PORT,
	PACKET_PG_OUTPUTS_STATES,
	PACKET_SECTIONS_STATES,
)
from custom_components.jablotron100.errors import ServiceUnavailable
from custom_components.jablotron100.jablotron import Jablotron


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("unload_ok", [False, True])
async def test_unload_only_stops_instance_after_platforms_unload(hass, unload_ok):
	instance = Mock()
	entry = SimpleNamespace(runtime_data=instance)
	with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(return_value=unload_ok)) as unload:
		assert await async_unload_entry(hass, entry) is unload_ok
		unload.assert_awaited_once_with(entry, PLATFORMS)
	if unload_ok:
		instance.shutdown.assert_called_once_with()
	else:
		instance.shutdown.assert_not_called()
	assert entry.runtime_data is instance


async def test_platform_unload_exception_leaves_instance_running(hass):
	instance = Mock()
	entry = SimpleNamespace(runtime_data=instance)
	with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(side_effect=RuntimeError("Synthetic unload failure"))):
		with pytest.raises(RuntimeError, match="Synthetic unload failure"):
			await async_unload_entry(hass, entry)
	instance.shutdown.assert_not_called()


@pytest.fixture
def check_executor(hass):
	loop_thread = threading.get_ident()

	def check():
		assert threading.get_ident() != loop_thread
		loop_responded = threading.Event()
		hass.loop.call_soon_threadsafe(loop_responded.set)
		assert loop_responded.wait(5)

	return check


@pytest.mark.parametrize("autodetect", [False, True])
async def test_initial_config_serial_probe_does_not_block_loop(hass, check_executor, autodetect):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow.context = {"source": "user"}
	serial_port = "/dev/jablotron-test-only"

	def detect():
		check_executor()
		return serial_port

	def probe(port):
		assert port == serial_port
		check_executor()

	with (
		patch.object(Jablotron, "detect_serial_port", side_effect=detect),
		patch("custom_components.jablotron100.config_flow.check_serial_port", side_effect=probe) as check_port,
	):
		result = await flow.async_step_user({
			CONF_SERIAL_PORT: AUTODETECT_SERIAL_PORT if autodetect else serial_port,
			CONF_PASSWORD: "1234",
			CONF_NUMBER_OF_DEVICES: 0,
			CONF_NUMBER_OF_PG_OUTPUTS: 0,
		})
	assert result["type"] == FlowResultType.CREATE_ENTRY
	check_port.assert_called_once_with(serial_port)


async def test_initial_config_probe_failure_preserves_form_error(hass, check_executor):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow.context = {"source": "user"}

	def probe(port):
		check_executor()
		raise ServiceUnavailable

	with patch("custom_components.jablotron100.config_flow.check_serial_port", side_effect=probe):
		result = await flow.async_step_user({
			CONF_SERIAL_PORT: "/dev/jablotron-test-only",
			CONF_PASSWORD: "1234",
			CONF_NUMBER_OF_DEVICES: 0,
			CONF_NUMBER_OF_PG_OUTPUTS: 0,
		})
	assert result["type"] == FlowResultType.FORM
	assert result["errors"] == {"base": "service_unavailable"}


async def test_runtime_autodetection_runs_entirely_in_executor(jablotron, check_executor):
	def detect():
		check_executor()
		return "/dev/jablotron-test-only"

	with patch.object(Jablotron, "detect_serial_port", side_effect=detect) as detect_port:
		assert await jablotron._detect_serial_port() == "/dev/jablotron-test-only"
	detect_port.assert_called_once_with()


async def test_initialize_offloads_detection_but_creates_entities_on_loop(jablotron, check_executor):
	loop_thread = threading.get_ident()
	steps = []
	sections_packet = Jablotron.create_packet(PACKET_SECTIONS_STATES, b"\x07\x00")
	pg_packet = Jablotron.create_packet(PACKET_PG_OUTPUTS_STATES, b"\x00")

	def detect(stage, result=None):
		check_executor()
		steps.append(stage)
		return result

	def create(stage):
		assert threading.get_ident() == loop_thread
		steps.append(stage)

	async def create_devices():
		create("create_devices")

	with (
		patch.object(jablotron, "_load_stored_data", new=AsyncMock()),
		patch("custom_components.jablotron100.jablotron.os.path.exists", return_value=True),
		patch.object(jablotron, "_detect_central_unit", side_effect=lambda: detect("central")),
		patch.object(jablotron, "_detect_devices", side_effect=lambda: detect("devices")),
		patch.object(jablotron, "_detect_sections_and_pg_outputs", side_effect=lambda: detect("sections", [sections_packet, pg_packet])),
		patch.object(jablotron, "_create_devices", side_effect=create_devices),
		patch.object(jablotron, "_create_sections", side_effect=lambda packet: create("create_sections")),
		patch.object(jablotron, "_parse_pg_outputs_states_packet", side_effect=lambda packet: create("parse_pg")),
		patch.object(jablotron, "_create_pg_outputs", side_effect=lambda: create("create_pg")),
		patch.object(jablotron, "_create_central_unit_sensors", side_effect=lambda: create("create_central")),
		patch("custom_components.jablotron100.jablotron.ThreadPoolExecutor") as executor,
	):
		try:
			await jablotron.initialize()
			assert executor.return_value.submit.call_count == 2
			assert jablotron.last_update_success
		finally:
			jablotron.shutdown()
	assert steps == ["central", "devices", "create_devices", "sections", "create_sections", "parse_pg", "create_pg", "create_central"]