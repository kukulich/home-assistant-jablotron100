from homeassistant.components.sensor import (
	SensorDeviceClass,
	SensorEntity,
	SensorEntityDescription,
	SensorStateClass,
)
from homeassistant.const import (
	PERCENTAGE,
	UnitOfElectricCurrent,
	UnitOfElectricPotential,
	UnitOfTemperature,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from typing import Dict
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
	EntityType,
)
from .jablotron import (
	Jablotron,
	JablotronControl,
	JablotronEntity,
)

SENSOR_TYPES: Dict[EntityType, SensorEntityDescription] = {
	EntityType.SIGNAL_STRENGTH: SensorEntityDescription(
		key=EntityType.SIGNAL_STRENGTH,
		state_class=SensorStateClass.MEASUREMENT,
		native_unit_of_measurement=PERCENTAGE,
		suggested_display_precision=0,
		entity_category=EntityCategory.DIAGNOSTIC,
		icon="mdi:wifi",
	),
	EntityType.BATTERY_LEVEL: SensorEntityDescription(
		key=EntityType.BATTERY_LEVEL,
		state_class=SensorStateClass.MEASUREMENT,
		native_unit_of_measurement=PERCENTAGE,
		suggested_display_precision=0,
		device_class=SensorDeviceClass.BATTERY,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.TEMPERATURE: SensorEntityDescription(
		key=EntityType.TEMPERATURE,
		state_class=SensorStateClass.MEASUREMENT,
		native_unit_of_measurement=UnitOfTemperature.CELSIUS,
		suggested_display_precision=1,
		device_class=SensorDeviceClass.TEMPERATURE,
	),
	EntityType.VOLTAGE: SensorEntityDescription(
		key=EntityType.VOLTAGE,
		state_class=SensorStateClass.MEASUREMENT,
		native_unit_of_measurement=UnitOfElectricPotential.VOLT,
		suggested_display_precision=1,
		device_class=SensorDeviceClass.VOLTAGE,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.CURRENT: SensorEntityDescription(
		key=EntityType.CURRENT,
		state_class=SensorStateClass.MEASUREMENT,
		native_unit_of_measurement=UnitOfElectricCurrent.MILLIAMPERE,
		suggested_display_precision=0,
		device_class=SensorDeviceClass.CURRENT,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.PULSE: SensorEntityDescription(
		key=EntityType.PULSE,
		state_class=SensorStateClass.TOTAL_INCREASING,
		suggested_display_precision=0,
	),
	EntityType.IP: SensorEntityDescription(
		key=EntityType.IP,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
}

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	@callback
	def add_entities() -> None:
		entities = []

		for entity_type in SENSOR_TYPES:
			for entity in jablotron_instance.entities[entity_type].values():
				if entity.id not in jablotron_instance.hass_entities:
					entities.append(JablotronSensor(jablotron_instance, entity, SENSOR_TYPES[entity_type]))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class JablotronSensor(JablotronEntity, SensorEntity):

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronControl,
		description: SensorEntityDescription,
	) -> None:
		self.entity_description = description

		super().__init__(jablotron, control)

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_name = self._control.name
		self._attr_native_value = self._get_state()
