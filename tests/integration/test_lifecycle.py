from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor
from functools import partial
import os
import sys
import threading
from types import SimpleNamespace
from unittest.mock import ANY, AsyncMock, Mock, mock_open, patch

from homeassistant.const import CONF_PASSWORD, EVENT_HOMEASSISTANT_STOP
from homeassistant.data_entry_flow import FlowResultType
import pytest

from custom_components.jablotron100 import PLATFORMS, async_setup_entry, async_unload_entry
from custom_components.jablotron100.config_flow import JablotronConfigFlow, check_serial_port
from custom_components.jablotron100.const import (
	AUTODETECT_SERIAL_PORT,
	CONF_DEVICES,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_SERIAL_PORT,
	DeviceType,
	PACKET_PG_OUTPUTS_STATES,
	PACKET_SECTIONS_STATES,
)
from custom_components.jablotron100.errors import ServiceUnavailable
from custom_components.jablotron100.jablotron import Jablotron
from custom_components.jablotron100.stream import JablotronReadStream


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("unload_ok", [False, True])
async def test_unload_only_stops_instance_after_platforms_unload(hass, unload_ok):
	instance = Mock(async_shutdown=AsyncMock())
	entry = SimpleNamespace(runtime_data=instance)
	with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(return_value=unload_ok)) as unload:
		assert await async_unload_entry(hass, entry) is unload_ok
		unload.assert_awaited_once_with(entry, PLATFORMS)
	if unload_ok:
		instance.async_shutdown.assert_awaited_once_with()
	else:
		instance.async_shutdown.assert_not_awaited()
	assert entry.runtime_data is instance


async def test_platform_unload_exception_leaves_instance_running(hass):
	instance = Mock(async_shutdown=AsyncMock())
	entry = SimpleNamespace(runtime_data=instance)
	with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(side_effect=RuntimeError("Synthetic unload failure"))):
		with pytest.raises(RuntimeError, match="Synthetic unload failure"):
			await async_unload_entry(hass, entry)
	instance.async_shutdown.assert_not_awaited()


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

	def probe(port, stop_event):
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
	check_port.assert_called_once_with(serial_port, ANY)


async def test_initial_config_probe_failure_preserves_form_error(hass, check_executor):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow.context = {"source": "user"}

	def probe(port, stop_event):
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


@pytest.mark.parametrize("trigger", ["unload", "ha_stop"])
async def test_shutdown_waits_for_workers_without_blocking_loop(hass, jablotron, check_executor, trigger):
	started = threading.Event()
	finished = threading.Event()
	entry = SimpleNamespace(runtime_data=jablotron)
	listeners_before = hass.bus.async_listeners().get(EVENT_HOMEASSISTANT_STOP, 0)

	def worker():
		started.set()
		assert jablotron._stream_stop_event.wait(5)
		check_executor()
		finished.set()

	executor = ThreadPoolExecutor(max_workers=1)
	jablotron._stream_thread_pool_executor = executor
	worker_future = executor.submit(worker)
	try:
		assert await hass.async_add_executor_job(started.wait, 5)
		with patch.object(jablotron, "_initialize", new=AsyncMock()):
			await jablotron.initialize()
		if trigger == "unload":
			with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(return_value=True)):
				assert await async_unload_entry(hass, entry)
		else:
			hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
			await hass.async_block_till_done()
		assert finished.is_set()
		assert worker_future.done()
		assert jablotron._stream_thread_pool_executor is None
		assert jablotron._remove_stop_listener is None
		listeners_after = hass.bus.async_listeners().get(EVENT_HOMEASSISTANT_STOP, 0)
		if trigger == "unload":
			assert listeners_after == listeners_before
		else:
			assert listeners_after <= listeners_before
		await jablotron.async_shutdown()
	finally:
		jablotron._stream_stop_event.set()
		await hass.async_add_executor_job(executor.shutdown, True)


@pytest.mark.parametrize("failed_stage", ["_load_stored_data", "_detect_central_unit", "_detect_devices", "_detect_sections_and_pg_outputs"])
async def test_failed_initialization_cleans_stop_listener(hass, jablotron, failed_stage):
	listeners_before = hass.bus.async_listeners().get(EVENT_HOMEASSISTANT_STOP, 0)
	with (
		patch.object(jablotron, "_load_stored_data", new=AsyncMock()),
		patch("custom_components.jablotron100.jablotron.os.path.exists", return_value=True),
		patch.object(jablotron, "_detect_central_unit"),
		patch.object(jablotron, "_detect_devices"),
		patch.object(jablotron, "_detect_sections_and_pg_outputs", return_value=[]),
		patch.object(jablotron, failed_stage, side_effect=ServiceUnavailable("Synthetic detection failure")),
	):
		with pytest.raises(ServiceUnavailable, match="Synthetic detection failure"):
			await jablotron.initialize()
	assert jablotron._stream_stop_event.is_set()
	assert jablotron._stream_thread_pool_executor is None
	assert hass.bus.async_listeners().get(EVENT_HOMEASSISTANT_STOP, 0) == listeners_before


async def test_cancelled_initialization_waits_for_detection_to_exit(hass, jablotron):
	started = asyncio.Event()
	finished = asyncio.Event()
	listeners_before = hass.bus.async_listeners().get(EVENT_HOMEASSISTANT_STOP, 0)

	def detect():
		hass.loop.call_soon_threadsafe(started.set)
		try:
			assert jablotron._stream_stop_event.wait(5)
		finally:
			hass.loop.call_soon_threadsafe(finished.set)

	with (
		patch.object(jablotron, "_load_stored_data", new=AsyncMock()),
		patch("custom_components.jablotron100.jablotron.os.path.exists", return_value=True),
		patch.object(jablotron, "_detect_central_unit", side_effect=detect),
	):
		task = hass.async_create_task(jablotron.initialize())
		try:
			await asyncio.wait_for(started.wait(), 5)
			task.cancel()
			with pytest.raises(asyncio.CancelledError):
				await task
			assert finished.is_set()
			assert jablotron._stream_thread_pool_executor is None
			assert hass.bus.async_listeners().get(EVENT_HOMEASSISTANT_STOP, 0) == listeners_before
		finally:
			jablotron._stream_stop_event.set()
			await asyncio.gather(task, return_exceptions=True)
			await asyncio.wait_for(finished.wait(), 5)


async def test_cancelled_config_flow_waits_for_probe_to_exit(hass):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow.context = {"source": "user"}
	started = asyncio.Event()
	finished = asyncio.Event()
	cleanup = threading.Event()

	def probe(port, stop_event=None):
		hass.loop.call_soon_threadsafe(started.set)
		try:
			assert (stop_event or cleanup).wait(5)
		finally:
			hass.loop.call_soon_threadsafe(finished.set)

	with patch("custom_components.jablotron100.config_flow.check_serial_port", side_effect=probe):
		task = hass.async_create_task(flow.async_step_user({
			CONF_SERIAL_PORT: "/dev/jablotron-test-only",
			CONF_PASSWORD: "1234",
			CONF_NUMBER_OF_DEVICES: 0,
			CONF_NUMBER_OF_PG_OUTPUTS: 0,
		}))
		try:
			await asyncio.wait_for(started.wait(), 5)
			task.cancel()
			with pytest.raises(asyncio.CancelledError):
				await task
			assert finished.is_set()
		finally:
			cleanup.set()
			await asyncio.gather(task, return_exceptions=True)
			await asyncio.wait_for(finished.wait(), 5)


@pytest.mark.parametrize("stage", ["probe", "_detect_central_unit", "_detect_sections_and_pg_outputs", "_detect_devices"])
async def test_detection_timeout_closes_stream_and_joins_workers(hass, jablotron, monkeypatch, stage):
	if sys.platform != "linux":
		pytest.skip("Uses Linux file descriptors like hidraw")
	read_fd, write_fd = os.pipe()
	serial_port = f"/proc/self/fd/{read_fd}"
	streams = []
	threads = []
	executors = []

	def open_reader(port, *stop_events):
		stream = JablotronReadStream(port, *stop_events)
		streams.append(stream)
		return stream

	def create_executor(**kwargs):
		executor = ThreadPoolExecutor(**kwargs)
		executors.append(executor)
		submit = executor.submit

		def run(callback):
			threads.append(threading.current_thread())
			return callback()

		executor.submit = lambda callback: submit(run, callback)
		return executor

	if stage == "probe":
		module = sys.modules[JablotronConfigFlow.__module__]
		monkeypatch.setattr(module, "JablotronReadStream", open_reader)
		monkeypatch.setattr(module, "open", mock_open(), raising=False)
		detect = partial(check_serial_port, serial_port)
	else:
		module = sys.modules[Jablotron.__module__]
		jablotron._serial_port = serial_port
		jablotron._config[CONF_NUMBER_OF_DEVICES] = 1
		jablotron._config[CONF_DEVICES] = [DeviceType.MOTION_DETECTOR.value]
		monkeypatch.setattr(jablotron, "_send_packet", Mock())
		monkeypatch.setattr(jablotron, "_send_packets", Mock())
		monkeypatch.setattr(jablotron, "_open_read_stream", lambda stop_event=None: open_reader(serial_port, jablotron._stream_stop_event, stop_event or jablotron._stream_stop_event))
		detect = getattr(jablotron, stage)
	monkeypatch.setattr(module, "ThreadPoolExecutor", create_executor)
	monkeypatch.setattr(module, "STREAM_TIMEOUT", 0.1)
	try:
		with pytest.raises(ServiceUnavailable):
			await hass.async_add_executor_job(detect)
		assert streams
		assert all(stream._stream.closed for stream in streams)
		assert threads
		assert all(not thread.is_alive() for thread in threads)
	finally:
		jablotron._stream_stop_event.set()
		for executor in executors:
			await hass.async_add_executor_job(executor.shutdown, True)
		os.close(read_fd)
		os.close(write_fd)


async def test_platform_setup_failure_stops_initialized_instance(hass, jablotron, entity_component):
	entity_component("binary_sensor")
	entry = hass.config_entries.async_get_entry("test-entry")
	with (
		patch("custom_components.jablotron100.Jablotron", return_value=jablotron),
		patch.object(jablotron, "initialize", new=AsyncMock()),
		patch.object(jablotron, "async_shutdown", new=AsyncMock()) as shutdown,
		patch.object(hass.config_entries, "async_forward_entry_setups", new=AsyncMock(side_effect=RuntimeError("Synthetic platform setup failure"))),
	):
		with pytest.raises(RuntimeError, match="Synthetic platform setup failure"):
			await async_setup_entry(hass, entry)
		shutdown.assert_awaited_once_with()