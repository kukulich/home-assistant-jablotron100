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
from .jablotron import Jablotron, JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronSignalStrengthEntity(jablotron_instance, control) for control in jablotron_instance.device_signal_strength_sensors()))
	async_add_entities((JablotronBatteryLevelEntity(jablotron_instance, control) for control in jablotron_instance.device_battery_level_sensors()))
	async_add_entities((JablotronTemperatureEntity(jablotron_instance, control) for control in jablotron_instance.device_temperature_sensors()))
	async_add_entities((JablotronVoltageEntity(jablotron_instance, control) for control in jablotron_instance.device_voltage_sensors()))
	async_add_entities((JablotronCurrentEntity(jablotron_instance, control) for control in jablotron_instance.device_current_sensors()))
	async_add_entities((JablotronPulseEntity(jablotron_instance, control) for control in jablotron_instance.device_pulse_sensors()))

	gsm_signal_strength_sensor = jablotron_instance.gsm_signal_strength_sensor()
	if gsm_signal_strength_sensor is not None:
		async_add_entities([JablotronSignalStrengthEntity(jablotron_instance, gsm_signal_strength_sensor)])

	lan_connection_ip = jablotron_instance.lan_connection_ip()
	if lan_connection_ip is not None:
		async_add_entities([JablotronLanIpEntity(jablotron_instance, lan_connection_ip)])


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


class JablotronPulseEntity(JablotronSensor):

	_attr_state_class = SensorStateClass.TOTAL_INCREASING


class JablotronLanIpEntity(JablotronSensor):

	_attr_state_class = None
	_attr_entity_category = EntityCategory.DIAGNOSTIC
