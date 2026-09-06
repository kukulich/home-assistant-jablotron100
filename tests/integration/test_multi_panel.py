from __future__ import annotations

import asyncio
import copy
import json
import logging
from pathlib import Path
from types import MappingProxyType
from unittest.mock import patch

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, EVENT_STATE_CHANGED, STATE_OFF, STATE_ON
from homeassistant.core import callback
from homeassistant.exceptions import ServiceValidationError
from homeassistant.helpers.entity_component import EntityComponent
from homeassistant.helpers.storage import Store
import pytest

from custom_components.jablotron100 import async_remove_entry, binary_sensor
from custom_components.jablotron100.const import (
	CONF_DEVICES, CONF_NUMBER_OF_DEVICES, CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_SERIAL_PORT, CONF_UNIQUE_ID, DOMAIN, EntityType,
)
from custom_components.jablotron100.jablotron import (
	Jablotron, JablotronCentralUnit, JablotronControl, STORAGE_VERSION,
	STORAGE_CENTRAL_UNIT_KEY, STORAGE_DEVICES_KEY, STORAGE_STATES_KEY,
)
from custom_components.jablotron100.storage import JablotronStore


@pytest.fixture
def panels(hass):
	result = []
	for entry_id in ("panel-a", "panel-b"):
		config = {
			CONF_UNIQUE_ID: entry_id, CONF_SERIAL_PORT: "/dev/test-only",
			CONF_PASSWORD: "1234", CONF_NUMBER_OF_DEVICES: 0,
			CONF_NUMBER_OF_PG_OUTPUTS: 0, CONF_DEVICES: [],
		}
		entry = ConfigEntry(
			entry_id=entry_id, domain=DOMAIN, title=entry_id, data=config,
			options={}, source="user", unique_id=entry_id, version=1, minor_version=1,
			discovery_keys=MappingProxyType({}), subentries_data=None,
		)
		hass.config_entries._entries[entry_id] = entry
		instance = Jablotron(hass, entry_id, config, {})
		instance._central_unit = JablotronCentralUnit(entry_id, "JA-103K", "1", "1")
		instance.last_update_success = True
		entry.runtime_data = instance
		result.append((entry, instance))
	return result


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse_order", [False, True])
@pytest.mark.parametrize("unload_first", [False, True])
async def test_reset_problem_targets_own_panel(hass, panels, reverse_order, unload_first):
	component = EntityComponent(logging.getLogger(__name__), "binary_sensor", hass)
	platforms = []
	loaded = list(reversed(panels)) if reverse_order else panels
	try:
		for entry, instance in loaded:
			for entity_type, control_id in ((EntityType.PROBLEM, "problem"), (EntityType.DEVICE_STATE_MOTION, "motion")):
				instance.entities[entity_type][control_id] = JablotronControl(instance.central_unit(), None, control_id)
				instance.entities_states[control_id] = STATE_ON
			platform = component._async_init_entity_platform(DOMAIN, None)
			platform.config_entry = entry
			platforms.append(platform)
			entities = []
			with patch.object(binary_sensor, "async_get_current_platform", return_value=platform):
				await binary_sensor.async_setup_entry(hass, entry, entities.extend)
			for entity in entities:
				entity.entity_id = f"binary_sensor.{entry.entry_id.replace('-', '_')}_{entity.control.id}"
			await platform.async_add_entities(entities)

		if unload_first:
			await platforms[0].async_reset()
		first_panel = loaded[0][1]
		target_panel = loaded[1][1]
		target = target_panel.hass_entities["problem"]
		state_written = hass.loop.create_future()

		@callback
		def state_changed(event):
			if event.data["entity_id"] == target.entity_id and event.data["new_state"].state == STATE_OFF:
				if not state_written.done():
					state_written.set_result(None)

		unsubscribe = hass.bus.async_listen(EVENT_STATE_CHANGED, state_changed)
		try:
			await hass.services.async_call(DOMAIN, "reset_problem", {"entity_id": target.entity_id}, blocking=True)
			async with asyncio.timeout(5):
				await state_written
		finally:
			unsubscribe()
		await hass.async_block_till_done()
		assert target_panel.entities_states["problem"] == STATE_OFF
		assert hass.states.get(target.entity_id).state == STATE_OFF
		assert first_panel.entities_states["problem"] == STATE_ON
		assert first_panel.central_unit().unique_id not in first_panel._stored_data
		motion = target_panel.hass_entities["motion"]
		with pytest.raises(ServiceValidationError):
			await hass.services.async_call(DOMAIN, "reset_problem", {"entity_id": motion.entity_id}, blocking=True)
		with pytest.raises(ServiceValidationError):
			await motion.async_reset_problem()
		assert target_panel.entities_states["motion"] == STATE_ON
	finally:
		for platform in platforms:
			await platform.async_reset()


async def read_stored_data(hass):
	path = Path(hass.config.path(".storage", DOMAIN))
	return json.loads(await hass.async_add_executor_job(path.read_text))["data"]


@pytest.mark.asyncio
async def test_panels_load_existing_shared_storage_once(hass, panels):
	stored = {
		entry.entry_id: {
			STORAGE_STATES_KEY: {"problem": STATE_ON},
			STORAGE_CENTRAL_UNIT_KEY: {"battery": True},
			STORAGE_DEVICES_KEY: {"device_1": {"section": 1}},
		}
		for entry, instance in panels
	}
	await Store(hass, STORAGE_VERSION, DOMAIN).async_save(stored)
	base_load = Store.async_load
	with patch.object(Store, "async_load", autospec=True, side_effect=base_load) as load:
		await asyncio.gather(*(instance._load_stored_data() for entry, instance in panels))
		assert load.await_count == 1
	first_panel, second_panel = (instance for entry, instance in panels)
	assert first_panel._store is second_panel._store
	assert first_panel._stored_data is second_panel._stored_data
	assert first_panel._stored_data == stored
	for entry, instance in panels:
		assert instance.entities_states == stored[entry.entry_id][STORAGE_STATES_KEY]
		assert instance._central_unit_data == stored[entry.entry_id][STORAGE_CENTRAL_UNIT_KEY]
		assert instance._devices_data == stored[entry.entry_id][STORAGE_DEVICES_KEY]
		instance._central_unit_data["battery"] = False
		assert instance._stored_data[entry.entry_id][STORAGE_CENTRAL_UNIT_KEY]["battery"] is True


@pytest.mark.asyncio
@pytest.mark.parametrize("reverse_order", [False, True])
async def test_interleaved_panel_saves_preserve_both_panels(hass, panels, reverse_order):
	ordered = list(reversed(panels)) if reverse_order else panels
	await asyncio.gather(*(instance._load_stored_data() for entry, instance in ordered))
	for entry, instance in ordered:
		instance._central_unit_data = {"model": entry.entry_id}
		instance._devices_data = {"device_1": {"section": 1}}
		instance._store_central_unit_data()
		instance._store_devices_data()
		instance._store_state("problem", STATE_ON)
		await instance._store.async_save(instance._data_to_store())
	first_entry, first_panel = ordered[0]
	second_entry, second_panel = ordered[1]
	first_panel._store_state("problem", STATE_OFF)
	second_panel._store_state("temperature", 23)
	await asyncio.gather(
		first_panel._store.async_save(first_panel._data_to_store()),
		second_panel._store.async_save(second_panel._data_to_store()),
	)
	stored = await read_stored_data(hass)
	assert set(stored) == {"panel-a", "panel-b"}
	assert stored[first_entry.entry_id][STORAGE_STATES_KEY] == {"problem": STATE_OFF}
	assert stored[second_entry.entry_id][STORAGE_STATES_KEY] == {"problem": STATE_ON, "temperature": 23}
	for entry, instance in ordered:
		assert stored[entry.entry_id][STORAGE_CENTRAL_UNIT_KEY] == {"model": entry.entry_id}
		assert stored[entry.entry_id][STORAGE_DEVICES_KEY] == {"device_1": {"section": 1}}
	reloaded = Jablotron(hass, first_entry.entry_id, first_entry.data, {})
	await reloaded._load_stored_data()
	assert reloaded._store is first_panel._store
	assert reloaded.entities_states["problem"] == STATE_OFF
	assert await JablotronStore(hass, STORAGE_VERSION).async_load() == stored


@pytest.mark.asyncio
@pytest.mark.parametrize("load_panels", [False, True])
async def test_removing_panel_preserves_other_data_and_pending_saves(hass, panels, load_panels):
	stored = {
		"panel-a": {STORAGE_STATES_KEY: {"problem": STATE_ON}},
		"panel-b": {STORAGE_STATES_KEY: {"problem": STATE_OFF}},
	}
	await Store(hass, STORAGE_VERSION, DOMAIN).async_save(stored)
	if load_panels:
		await asyncio.gather(*(instance._load_stored_data() for entry, instance in panels))
	first_entry, first_panel = panels[0]
	second_entry, second_panel = panels[1]
	if load_panels:
		first_panel._store.async_delay_save(first_panel._data_to_store, delay=60)
	await async_remove_entry(hass, first_entry)
	assert await read_stored_data(hass) == {"panel-b": stored["panel-b"]}
	await second_panel._load_stored_data()
	second_panel._store_state("temperature", 24)
	await second_panel._store.async_save(second_panel._data_to_store())
	expected = {"panel-b": copy.deepcopy(stored["panel-b"])}
	expected["panel-b"][STORAGE_STATES_KEY]["temperature"] = 24
	assert await read_stored_data(hass) == expected
	assert "panel-a" not in first_panel._stored_data
	await async_remove_entry(hass, first_entry)
	assert await read_stored_data(hass) == expected