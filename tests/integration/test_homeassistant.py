from __future__ import annotations

import importlib
from functools import partial
from pathlib import Path
from unittest.mock import patch

import homeassistant
from homeassistant.components.binary_sensor import BinarySensorDeviceClass
from homeassistant.const import CONF_PASSWORD, STATE_OFF, STATE_ON, STATE_UNAVAILABLE
from homeassistant.data_entry_flow import FlowResultType
import pytest
import voluptuous as vol

from custom_components.jablotron100.config_flow import JablotronConfigFlow, get_devices_fields
from custom_components.jablotron100.const import (
	AUTODETECT_SERIAL_PORT,
	CONF_DEVICES,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_SERIAL_PORT,
	DeviceType,
	EntityType,
	MAX_DEVICES,
)
from custom_components.jablotron100.binary_sensor import BINARY_SENSOR_TYPES, JablotronBinarySensor
from custom_components.jablotron100.jablotron import JablotronControl, JablotronProgrammableOutput
from custom_components.jablotron100.sensor import SENSOR_TYPES, JablotronSensor
from custom_components.jablotron100.switch import JablotronProgrammableOutputEntity


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("module", [
	"__init__", "alarm_control_panel", "binary_sensor", "config_flow", "diagnostics",
	"event", "sensor", "switch",
])
async def test_imports_use_real_homeassistant(module):
	assert homeassistant.__file__ is not None
	assert Path(homeassistant.__file__).is_file()
	importlib.import_module(f"custom_components.jablotron100.{module}")


async def test_user_form_defaults_and_device_limit(hass):
	flow = JablotronConfigFlow()
	flow.hass = hass
	result = await flow.async_step_user()

	assert result["type"] == FlowResultType.FORM
	assert result["step_id"] == "user"
	assert result["errors"] == {}
	values = result["data_schema"]({CONF_PASSWORD: "1234"})
	assert values[CONF_SERIAL_PORT] == AUTODETECT_SERIAL_PORT
	assert values[CONF_NUMBER_OF_DEVICES] == 0
	assert values[CONF_NUMBER_OF_PG_OUTPUTS] == 0
	with pytest.raises(vol.Invalid):
		result["data_schema"]({CONF_PASSWORD: "1234", CONF_NUMBER_OF_DEVICES: MAX_DEVICES + 1})


async def test_device_selectors_preserve_assignments():
	schema = vol.Schema(get_devices_fields(2, [DeviceType.MOTION_DETECTOR, DeviceType.EMPTY]))
	assert schema({}) == {"device_001": "motion_detector", "device_002": "empty"}
	with pytest.raises(vol.Invalid):
		schema({"device_001": "not_a_device_type"})


async def test_device_step_creates_ordered_configuration(hass):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow._config = {CONF_NUMBER_OF_DEVICES: 2, CONF_DEVICES: []}
	result = await flow.async_step_devices({"device_002": "empty", "device_001": "motion_detector"})

	assert result["type"] == FlowResultType.CREATE_ENTRY
	assert result["data"][CONF_DEVICES] == ["motion_detector", "empty"]


async def test_storage_round_trip(jablotron):
	jablotron._store_state("device_temperature_sensor_1", 21.5)
	await jablotron._hass.async_block_till_done()
	await jablotron._store.async_save(jablotron._data_to_store())
	jablotron.entities_states.clear()
	await jablotron._load_stored_data()

	assert jablotron.entities_states["device_temperature_sensor_1"] == 21.5


async def test_sensor_lifecycle_and_state_update(hass, jablotron, entity_component):
	control = JablotronControl(jablotron.central_unit(), None, "temperature")
	jablotron.entities_states[control.id] = 21.5
	entity = JablotronSensor(jablotron, control, SENSOR_TYPES[EntityType.TEMPERATURE])
	entity.entity_id = "sensor.jablotron_test_temperature"
	component = entity_component("sensor")
	try:
		await component.async_add_entities([entity])
		assert jablotron.hass_entities[control.id] is entity
		assert hass.states.get(entity.entity_id).state == "21.5"
		await hass.async_add_executor_job(partial(jablotron._update_entity_state, control.id, 22.0, store_state=False))
		await hass.async_block_till_done()
		assert hass.states.get(entity.entity_id).state == "22.0"
	finally:
		await entity.async_remove()
	assert component.get_entity(entity.entity_id) is None
	assert hass.states.get(entity.entity_id).state == STATE_UNAVAILABLE


async def test_binary_sensor_state_and_device_class(hass, jablotron, entity_component):
	control = JablotronControl(jablotron.central_unit(), None, "problem")
	jablotron.entities_states[control.id] = STATE_OFF
	entity = JablotronBinarySensor(jablotron, control, BINARY_SENSOR_TYPES[EntityType.PROBLEM])
	entity.entity_id = "binary_sensor.jablotron_test_problem"
	component = entity_component("binary_sensor")
	try:
		await component.async_add_entities([entity])
		assert hass.states.get(entity.entity_id).state == STATE_OFF
		assert entity.device_class == BinarySensorDeviceClass.PROBLEM
		await hass.async_add_executor_job(partial(jablotron._update_entity_state, control.id, STATE_ON, store_state=False))
		await hass.async_block_till_done()
		assert hass.states.get(entity.entity_id).state == STATE_ON
	finally:
		await entity.async_remove()


async def test_switch_service_dispatch(hass, jablotron, entity_component):
	control = JablotronProgrammableOutput(jablotron.central_unit(), "pg_output_1", "PG output 1", 1)
	jablotron.entities_states[control.id] = STATE_OFF
	entity = JablotronProgrammableOutputEntity(jablotron, control)
	entity.entity_id = "switch.jablotron_test_output"
	component = entity_component("switch")
	component.async_register_entity_service("turn_on", {}, "async_turn_on")
	try:
		await component.async_add_entities([entity])
		with patch.object(jablotron, "_send_packet") as send_packet:
			await hass.services.async_call("switch", "turn_on", {"entity_id": entity.entity_id}, blocking=True)
			send_packet.assert_called_once_with(bytes.fromhex("8003230001"))
		await hass.async_block_till_done()
		assert hass.states.get(entity.entity_id).state == STATE_ON
	finally:
		await entity.async_remove()