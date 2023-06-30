from homeassistant.components.switch import (
	SwitchDeviceClass,
	SwitchEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_ON, STATE_OFF
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
	EntityType,
)
from .jablotron import Jablotron, JablotronProgrammableOutput, JablotronEntity


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

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

	_attr_name = None
	_attr_device_class = SwitchDeviceClass.SWITCH

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON

	async def async_turn_on(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_ON)
		self.update_state(STATE_ON)

	async def async_turn_off(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_OFF)
		self.update_state(STATE_OFF)
