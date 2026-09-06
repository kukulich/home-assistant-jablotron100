from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from unittest.mock import call, patch

from homeassistant.const import STATE_OFF, STATE_ON
import pytest

from custom_components.jablotron100.binary_sensor import BINARY_SENSOR_TYPES, JablotronBinarySensor
from custom_components.jablotron100.const import EntityType
from custom_components.jablotron100.jablotron import JablotronControl, JablotronProgrammableOutput, STORAGE_STATES_KEY
from custom_components.jablotron100.switch import JablotronProgrammableOutputEntity


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("store_state", [False, True])
async def test_worker_state_burst_keeps_entity_and_storage_consistent(hass, jablotron, entity_component, store_state):
	control = JablotronControl(jablotron.central_unit(), None, "problem")
	jablotron.entities_states[control.id] = STATE_OFF
	jablotron._store_state(control.id, STATE_ON)
	entity = JablotronBinarySensor(jablotron, control, BINARY_SENSOR_TYPES[EntityType.PROBLEM])
	entity.entity_id = "binary_sensor.jablotron_burst_problem"
	component = entity_component("binary_sensor")

	def send_states():
		for state in (STATE_ON, STATE_ON, STATE_OFF):
			jablotron._update_entity_state(control.id, state, store_state=store_state)

	try:
		await component.async_add_entities([entity])
		with patch.object(entity, "update_state", wraps=entity.update_state) as update_state:
			with ThreadPoolExecutor(max_workers=1) as executor:
				executor.submit(send_states).result(timeout=5)
			await hass.async_block_till_done()
			assert update_state.call_args_list == [call(STATE_ON), call(STATE_OFF)]

		assert jablotron.entities_states[control.id] == STATE_OFF
		assert hass.states.get(entity.entity_id).state == STATE_OFF
		stored_states = jablotron._data_to_store()[jablotron._get_unique_id()][STORAGE_STATES_KEY]
		assert stored_states[control.id] == (STATE_OFF if store_state else STATE_ON)
		await jablotron._store.async_save(jablotron._data_to_store())
		await jablotron._load_stored_data()
		assert jablotron.entities_states[control.id] == stored_states[control.id]
	finally:
		await entity.async_remove()


async def test_truncated_pg_packet_preserves_live_and_stored_on_state(hass, jablotron, entity_component):
	control = JablotronProgrammableOutput(jablotron.central_unit(), "pg_output_1", "PG output 1", 1)
	jablotron.entities_states[control.id] = STATE_ON
	jablotron._store_state(control.id, STATE_ON)
	entity = JablotronProgrammableOutputEntity(jablotron, control)
	entity.entity_id = "switch.jablotron_packet_output"
	component = entity_component("switch")
	try:
		await component.async_add_entities([entity])
		await hass.async_add_executor_job(jablotron._parse_pg_outputs_states_packet, bytes.fromhex("5001"))
		await hass.async_block_till_done()
		assert hass.states.get(entity.entity_id).state == STATE_ON
		assert jablotron.entities_states[control.id] == STATE_ON
		assert jablotron._data_to_store()[jablotron._get_unique_id()][STORAGE_STATES_KEY][control.id] == STATE_ON
	finally:
		await entity.async_remove()