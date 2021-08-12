from homeassistant import config_entries, core
from homeassistant.components.sensor import (
	DEVICE_CLASS_BATTERY,
	DEVICE_CLASS_SIGNAL_STRENGTH,
	SensorEntity,
	STATE_CLASS_MEASUREMENT,
)
from homeassistant.const import PERCENTAGE
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
)
from .jablotron import JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronSignalStrengthEntity(jablotron, control) for control in jablotron.device_signal_strength_sensors()))
	async_add_entities((JablotronBatteryLevelEntity(jablotron, control) for control in jablotron.device_battery_level_sensors()))

	gsm_signal_strength_sensor = jablotron.gsm_signal_strength_sensor()
	if gsm_signal_strength_sensor is not None:
		async_add_entities([JablotronSignalStrengthEntity(jablotron, gsm_signal_strength_sensor)])


class JablotronSensor(JablotronEntity, SensorEntity):

	_attr_unit_of_measurement = PERCENTAGE
	_attr_state_class = STATE_CLASS_MEASUREMENT

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_state = self._get_state()


class JablotronSignalStrengthEntity(JablotronSensor):

	_attr_device_class = DEVICE_CLASS_SIGNAL_STRENGTH


class JablotronBatteryLevelEntity(JablotronSensor):

	_attr_device_class = DEVICE_CLASS_BATTERY
