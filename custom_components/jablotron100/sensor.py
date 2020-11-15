from homeassistant import config_entries, core
from homeassistant.components.sensor import DEVICE_CLASS_BATTERY
from homeassistant.const import PERCENTAGE
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
)
from .jablotron import JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronBatteryLevelEntity(jablotron, control) for control in jablotron.device_battery_level_sensors()), True)


class JablotronBatteryLevelEntity(JablotronEntity):

	@property
	def device_class(self):
		return DEVICE_CLASS_BATTERY

	@property
	def unit_of_measurement(self):
		return PERCENTAGE
