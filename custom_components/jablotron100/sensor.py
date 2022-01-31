from homeassistant import config_entries, core
from homeassistant.components.sensor import (
	SensorDeviceClass,
	SensorEntity,
	SensorStateClass,
)
from homeassistant.const import (
	ELECTRIC_CURRENT_MILLIAMPERE,
	ELECTRIC_POTENTIAL_VOLT,
	PERCENTAGE,
	TEMP_CELSIUS,
)
from homeassistant.helpers.entity import EntityCategory
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
)
from .jablotron import JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronSignalStrengthEntity(jablotron, control) for control in jablotron.device_signal_strength_sensors()))
	async_add_entities((JablotronBatteryLevelEntity(jablotron, control) for control in jablotron.device_battery_level_sensors()))
	async_add_entities((JablotronTemperatureEntity(jablotron, control) for control in jablotron.device_temperature_sensors()))
	async_add_entities((JablotronVoltageEntity(jablotron, control) for control in jablotron.device_voltage_sensors()))
	async_add_entities((JablotronCurrentEntity(jablotron, control) for control in jablotron.device_current_sensors()))

	gsm_signal_strength_sensor = jablotron.gsm_signal_strength_sensor()
	if gsm_signal_strength_sensor is not None:
		async_add_entities([JablotronSignalStrengthEntity(jablotron, gsm_signal_strength_sensor)])


class JablotronSensor(JablotronEntity, SensorEntity):

	_attr_state_class = SensorStateClass.MEASUREMENT

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_native_value = self._get_state()


class JablotronSignalStrengthEntity(JablotronSensor):

	_attr_native_unit_of_measurement = PERCENTAGE
	_attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
	_attr_entity_category = EntityCategory.DIAGNOSTIC


class JablotronBatteryLevelEntity(JablotronSensor):

	_attr_native_unit_of_measurement = PERCENTAGE
	_attr_device_class = SensorDeviceClass.BATTERY
	_attr_entity_category = EntityCategory.DIAGNOSTIC


class JablotronTemperatureEntity(JablotronSensor):

	_attr_native_unit_of_measurement = TEMP_CELSIUS
	_attr_device_class = SensorDeviceClass.TEMPERATURE


class JablotronVoltageEntity(JablotronSensor):

	_attr_native_unit_of_measurement = ELECTRIC_POTENTIAL_VOLT
	_attr_device_class = SensorDeviceClass.VOLTAGE
	_attr_entity_category = EntityCategory.DIAGNOSTIC


class JablotronCurrentEntity(JablotronSensor):

	_attr_native_unit_of_measurement = ELECTRIC_CURRENT_MILLIAMPERE
	_attr_device_class = SensorDeviceClass.CURRENT
	_attr_entity_category = EntityCategory.DIAGNOSTIC
