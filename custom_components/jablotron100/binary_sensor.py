from __future__ import annotations
from homeassistant.components.binary_sensor import (
	BinarySensorDeviceClass,
	BinarySensorEntityDescription,
	BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant, ServiceCall
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import async_get_current_platform, AddEntitiesCallback
from homeassistant.const import (
	STATE_ON,
)

from typing import Dict
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
	EntityType,
)
from .jablotron import Jablotron, JablotronControl, JablotronEntity

BINARY_SENSOR_TYPES: Dict[EntityType, BinarySensorEntityDescription] = {
	EntityType.BATTERY_PROBLEM: BinarySensorEntityDescription(
		key=EntityType.BATTERY_PROBLEM,
		device_class=BinarySensorDeviceClass.PROBLEM,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.DEVICE_STATE_MOTION: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_MOTION,
		device_class=BinarySensorDeviceClass.MOTION,
	),
	EntityType.DEVICE_STATE_WINDOW: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_WINDOW,
		device_class=BinarySensorDeviceClass.WINDOW,
	),
	EntityType.DEVICE_STATE_DOOR: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_DOOR,
		device_class=BinarySensorDeviceClass.DOOR,
	),
	EntityType.DEVICE_STATE_GARAGE_DOOR: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_GARAGE_DOOR,
		device_class=BinarySensorDeviceClass.GARAGE_DOOR,
	),
	EntityType.DEVICE_STATE_GLASS: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_GLASS,
	),
	EntityType.DEVICE_STATE_MOISTURE: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_MOISTURE,
		device_class=BinarySensorDeviceClass.MOISTURE,
	),
	EntityType.DEVICE_STATE_GAS: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_GAS,
		device_class=BinarySensorDeviceClass.GAS,
	),
	EntityType.DEVICE_STATE_SMOKE: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_SMOKE,
		device_class=BinarySensorDeviceClass.SMOKE,
	),
	EntityType.DEVICE_STATE_LOCK: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_LOCK,
		device_class=BinarySensorDeviceClass.LOCK,
	),
	EntityType.DEVICE_STATE_TAMPER: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_TAMPER,
		device_class=BinarySensorDeviceClass.TAMPER,
	),
	EntityType.DEVICE_STATE_THERMOSTAT: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_THERMOSTAT,
	),
	EntityType.DEVICE_STATE_THERMOMETER: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_THERMOMETER,
	),
	EntityType.DEVICE_STATE_INDOOR_SIREN_BUTTON: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_INDOOR_SIREN_BUTTON,
	),
	EntityType.DEVICE_STATE_BUTTON: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_BUTTON,
	),
	EntityType.DEVICE_STATE_VALVE: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_VALVE,
	),
	EntityType.DEVICE_STATE_CUSTOM: BinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_CUSTOM,
	),
	EntityType.FIRE: BinarySensorEntityDescription(
		key=EntityType.FIRE,
	),
	EntityType.GSM_SIGNAL: BinarySensorEntityDescription(
		key=EntityType.GSM_SIGNAL,
		device_class=BinarySensorDeviceClass.CONNECTIVITY,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.LAN_CONNECTION: BinarySensorEntityDescription(
		key=EntityType.LAN_CONNECTION,
		device_class=BinarySensorDeviceClass.CONNECTIVITY,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.POWER_SUPPLY: BinarySensorEntityDescription(
		key=EntityType.POWER_SUPPLY,
		device_class=BinarySensorDeviceClass.PROBLEM,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.PROBLEM: BinarySensorEntityDescription(
		key=EntityType.PROBLEM,
		device_class=BinarySensorDeviceClass.PROBLEM,
		entity_category=EntityCategory.DIAGNOSTIC,
	)
}

async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	@callback
	def add_entities() -> None:
		entities = []

		for entity_type in BINARY_SENSOR_TYPES:
			for entity in jablotron_instance.entities[entity_type].values():
				if entity.id not in jablotron_instance.hass_entities:
					entities.append(JablotronBinarySensor(jablotron_instance, entity, BINARY_SENSOR_TYPES[entity_type]))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)

	async def reset_problem(entity: JablotronEntity, service_call: ServiceCall) -> None:
		jablotron_instance.reset_problem_sensor(entity.control)

	platform = async_get_current_platform()

	platform.async_register_entity_service(
		"reset_problem",
		{},
		reset_problem,
	)


class JablotronBinarySensor(JablotronEntity, BinarySensorEntity):

	entity_description: BinarySensorEntityDescription

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronControl,
		description: BinarySensorEntityDescription,
	) -> None:
		self.entity_description = description
		self._attr_translation_key = description.key

		super().__init__(jablotron, control)

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON
