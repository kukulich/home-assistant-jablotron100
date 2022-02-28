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
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
	EntityType,
)
from .jablotron import Jablotron, JablotronEntity


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	@callback
	def add_entities() -> None:
		entities = []

		mapping = {
			EntityType.SIGNAL_STRENGTH: JablotronSignalStrengthEntity,
			EntityType.BATTERY_LEVEL: JablotronBatteryLevelEntity,
			EntityType.TEMPERATURE: JablotronTemperatureEntity,
			EntityType.VOLTAGE: JablotronVoltageEntity,
			EntityType.CURRENT: JablotronCurrentEntity,
			EntityType.PULSE: JablotronPulseEntity,
			EntityType.IP: JablotronIpEntity,
		}

		for entity_type, entity_class in mapping.items():
			for entity in jablotron_instance.entities[entity_type].values():
				if entity.id not in jablotron_instance.hass_entities:
					entities.append(entity_class(jablotron_instance, entity))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


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


class JablotronIpEntity(JablotronSensor):

	_attr_state_class = None
	_attr_entity_category = EntityCategory.DIAGNOSTIC
