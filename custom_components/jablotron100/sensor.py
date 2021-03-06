from homeassistant import config_entries, core
from homeassistant.components.sensor import DEVICE_CLASS_BATTERY, DEVICE_CLASS_SIGNAL_STRENGTH
from homeassistant.const import PERCENTAGE
from homeassistant.helpers.typing import StateType
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
)
from .jablotron import JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronSignalStrengthEntity(jablotron, control) for control in jablotron.device_signal_strength_sensors()), True)
	async_add_entities((JablotronBatteryLevelEntity(jablotron, control) for control in jablotron.device_battery_level_sensors()), True)

	gsm_signal_strength_sensor = jablotron.gsm_signal_strength_sensor()
	if gsm_signal_strength_sensor is not None:
		async_add_entities([JablotronSignalStrengthEntity(jablotron, gsm_signal_strength_sensor)], True)


class JablotronSignalStrengthEntity(JablotronEntity):

	@property
	def state(self) -> StateType:
		return self._state

	@property
	def device_class(self):
		return DEVICE_CLASS_SIGNAL_STRENGTH

	@property
	def unit_of_measurement(self):
		return PERCENTAGE


class JablotronBatteryLevelEntity(JablotronEntity):

	@property
	def state(self) -> StateType:
		return self._state

	@property
	def device_class(self):
		return DEVICE_CLASS_BATTERY

	@property
	def unit_of_measurement(self):
		return PERCENTAGE
