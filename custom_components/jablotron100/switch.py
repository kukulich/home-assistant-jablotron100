from homeassistant.components.switch import (
	SwitchDeviceClass,
	SwitchEntity,
)
from homeassistant.const import STATE_ON, STATE_OFF
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from . import JablotronConfigEntry
from .const import EntityType
from .jablotron import Jablotron, JablotronProgrammableOutput, JablotronEntity


async def async_setup_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = config_entry.runtime_data

	@callback
	def add_entities() -> None:
		entities = []

		for entity in jablotron_instance.entities[EntityType.PROGRAMMABLE_OUTPUT].values():
			if entity.id not in jablotron_instance.hass_entities:
				entities.append(JablotronProgrammableOutputEntity(jablotron_instance, entity))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class JablotronProgrammableOutputEntity(JablotronEntity, SwitchEntity):

	_control: JablotronProgrammableOutput

	_attr_device_class = SwitchDeviceClass.SWITCH
	_attr_translation_key = "pg_output"

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronProgrammableOutput,
	) -> None:
		super().__init__(jablotron, control)

		self._attr_translation_placeholders = {
			"pgOutputNo": control.pg_output_number,
		}

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON

	async def async_turn_on(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_ON)
		self.update_state(STATE_ON)

	async def async_turn_off(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_OFF)
		self.update_state(STATE_OFF)
