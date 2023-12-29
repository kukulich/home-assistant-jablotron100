from __future__ import annotations
from collections.abc import Callable
from dataclasses import dataclass
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

@dataclass(frozen=True, kw_only=True)
class JablotronBinarySensorEntityDescription(BinarySensorEntityDescription):
	icon_func: Callable | None = None

BINARY_SENSOR_TYPES: Dict[EntityType, JablotronBinarySensorEntityDescription] = {
	EntityType.BATTERY_PROBLEM: JablotronBinarySensorEntityDescription(
		key=EntityType.BATTERY_PROBLEM,
		device_class=BinarySensorDeviceClass.PROBLEM,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.DEVICE_STATE_MOTION: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_MOTION,
		device_class=BinarySensorDeviceClass.MOTION,
	),
	EntityType.DEVICE_STATE_WINDOW: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_WINDOW,
		device_class=BinarySensorDeviceClass.WINDOW,
	),
	EntityType.DEVICE_STATE_DOOR: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_DOOR,
		device_class=BinarySensorDeviceClass.DOOR,
	),
	EntityType.DEVICE_STATE_GARAGE_DOOR: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_GARAGE_DOOR,
		device_class=BinarySensorDeviceClass.GARAGE_DOOR,
	),
	EntityType.DEVICE_STATE_GLASS: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_GLASS,
		icon_func=lambda is_on: "mdi:image-broken-variant" if is_on else "mdi:square-outline"
	),
	EntityType.DEVICE_STATE_MOISTURE: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_MOISTURE,
		device_class=BinarySensorDeviceClass.MOISTURE,
	),
	EntityType.DEVICE_STATE_GAS: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_GAS,
		device_class=BinarySensorDeviceClass.GAS,
	),
	EntityType.DEVICE_STATE_SMOKE: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_SMOKE,
		device_class=BinarySensorDeviceClass.SMOKE,
	),
	EntityType.DEVICE_STATE_LOCK: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_LOCK,
		device_class=BinarySensorDeviceClass.LOCK,
	),
	EntityType.DEVICE_STATE_TAMPER: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_TAMPER,
		device_class=BinarySensorDeviceClass.TAMPER,
	),
	EntityType.DEVICE_STATE_THERMOSTAT: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_THERMOSTAT,
		icon_func=lambda is_on: "mdi:thermometer" if is_on else "mdi:thermometer-off",
	),
	EntityType.DEVICE_STATE_THERMOMETER: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_THERMOMETER,
	),
	EntityType.DEVICE_STATE_INDOOR_SIREN_BUTTON: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_INDOOR_SIREN_BUTTON,
		icon_func=lambda is_on: "mdi:gesture-tap-box" if is_on else "mdi:circle-box-outline",
	),
	EntityType.DEVICE_STATE_BUTTON: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_BUTTON,
		icon_func=lambda is_on: "mdi:gesture-double-tap" if is_on else "mdi:circle-double"
	),
	EntityType.DEVICE_STATE_VALVE: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_VALVE,
		icon_func=lambda is_on: "mdi:valve-open" if is_on else "mdi:valve-closed",
	),
	EntityType.DEVICE_STATE_CUSTOM: JablotronBinarySensorEntityDescription(
		key=EntityType.DEVICE_STATE_CUSTOM,
	),
	EntityType.FIRE: JablotronBinarySensorEntityDescription(
		key=EntityType.FIRE,
		icon_func=lambda is_on: "mdi:fire" if is_on else "mdi:fire-off",
	),
	EntityType.GSM_SIGNAL: JablotronBinarySensorEntityDescription(
		key=EntityType.GSM_SIGNAL,
		device_class=BinarySensorDeviceClass.CONNECTIVITY,
		entity_category=EntityCategory.DIAGNOSTIC,
		icon_func=lambda is_on: "mdi:signal" if is_on else "mdi:signal-off",
	),
	EntityType.LAN_CONNECTION: JablotronBinarySensorEntityDescription(
		key=EntityType.LAN_CONNECTION,
		device_class=BinarySensorDeviceClass.CONNECTIVITY,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.POWER_SUPPLY: JablotronBinarySensorEntityDescription(
		key=EntityType.POWER_SUPPLY,
		device_class=BinarySensorDeviceClass.PROBLEM,
		entity_category=EntityCategory.DIAGNOSTIC,
	),
	EntityType.PROBLEM: JablotronBinarySensorEntityDescription(
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

	entity_description: JablotronBinarySensorEntityDescription

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronControl,
		description: JablotronBinarySensorEntityDescription,
	) -> None:
		self.entity_description = description
		self._attr_translation_key = description.key

		super().__init__(jablotron, control)

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON

		if self.entity_description.icon_func is not None:
			self._attr_icon = self.entity_description.icon_func(self._attr_is_on)
