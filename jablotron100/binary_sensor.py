from homeassistant import config_entries, core
from homeassistant.components.binary_sensor import (
	BinarySensorEntity,
	DEVICE_CLASS_PROBLEM,
)
from homeassistant.const import STATE_ON
from .const import DATA_JABLOTRON, DOMAIN
from .jablotron import JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronBinarySensorEntity(jablotron, control) for control in jablotron.section_problem_sensors()), True)


class JablotronBinarySensorEntity(JablotronEntity, BinarySensorEntity):

	@property
	def is_on(self) -> bool:
		return self.state == STATE_ON

	@property
	def device_class(self) -> str:
		return DEVICE_CLASS_PROBLEM

	def _device_id(self) -> str:
		return self._control.name

	def _device_name(self) -> str:
		return self._control.name
