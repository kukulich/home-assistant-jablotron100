from __future__ import annotations

from unittest.mock import Mock, call

from homeassistant.const import STATE_OFF, STATE_ON
import pytest

from custom_components.jablotron100.jablotron import Jablotron


@pytest.fixture
def state_updates():
	jablotron = object.__new__(Jablotron)
	jablotron.entities_states = {"problem": STATE_OFF}
	jablotron._store_state = Mock()
	callbacks = []
	jablotron._hass = Mock()
	jablotron._hass.loop.call_soon_threadsafe.side_effect = lambda callback, *args: callbacks.append((callback, args))
	entity = Mock()
	entity.update_state.side_effect = lambda state: jablotron.entities_states.update(problem=state)
	jablotron.hass_entities = {"problem": entity}
	return jablotron, entity, callbacks


@pytest.mark.parametrize("store_state", [False, True])
def test_queued_states_apply_in_order_without_dropping_return_to_initial_state(state_updates, store_state):
	jablotron, entity, callbacks = state_updates
	for state in (STATE_ON, STATE_ON, STATE_OFF):
		jablotron._update_entity_state("problem", state, store_state=store_state)

	assert jablotron.entities_states["problem"] == STATE_OFF
	entity.update_state.assert_not_called()
	jablotron._store_state.assert_not_called()
	for callback, args in callbacks:
		callback(*args)

	assert entity.update_state.call_args_list == [call(STATE_ON), call(STATE_OFF)]
	assert jablotron.entities_states["problem"] == STATE_OFF
	if store_state:
		assert jablotron._store_state.call_args_list == [
			call("problem", STATE_ON), call("problem", STATE_ON), call("problem", STATE_OFF),
		]
	else:
		jablotron._store_state.assert_not_called()


def test_queued_state_handles_entity_unsubscribed_before_callback(state_updates):
	jablotron, entity, callbacks = state_updates
	jablotron._update_entity_state("problem", STATE_ON, store_state=False)
	jablotron.hass_entities.clear()
	for callback, args in callbacks:
		callback(*args)
	assert jablotron.entities_states["problem"] == STATE_ON
	entity.update_state.assert_not_called()


def test_unregistered_state_remains_available_during_initialization(state_updates):
	jablotron, entity, callbacks = state_updates
	jablotron.hass_entities.clear()
	jablotron._update_entity_state("problem", STATE_ON)
	assert jablotron.entities_states["problem"] == STATE_ON
	jablotron._store_state.assert_called_once_with("problem", STATE_ON)
	assert callbacks == []