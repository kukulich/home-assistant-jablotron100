from __future__ import annotations
from homeassistant.components.binary_sensor import (
	BinarySensorDeviceClass,
	BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.const import (
	STATE_ON,
)

from typing import Final
from .const import (
	DATA_JABLOTRON,
	DEVICE_MOTION_DETECTOR,
	DEVICE_WINDOW_OPENING_DETECTOR,
	DEVICE_DOOR_OPENING_DETECTOR,
	DEVICE_GARAGE_DOOR_OPENING_DETECTOR,
	DEVICE_GLASS_BREAK_DETECTOR,
	DEVICE_SMOKE_DETECTOR,
	DEVICE_FLOOD_DETECTOR,
	DEVICE_GAS_DETECTOR,
	DEVICE_KEY_FOB,
	DEVICE_SIREN_INDOOR,
	DEVICE_BUTTON,
	DEVICE_THERMOSTAT,
	DEVICE_LOCK,
	DEVICE_TAMPER,
	DOMAIN,
	EntityType,
)
from .jablotron import Jablotron, JablotronDevice, JablotronEntity

DEVICE_CLASSES: Final = {
	DEVICE_MOTION_DETECTOR: BinarySensorDeviceClass.MOTION,
	DEVICE_WINDOW_OPENING_DETECTOR: BinarySensorDeviceClass.WINDOW,
	DEVICE_DOOR_OPENING_DETECTOR: BinarySensorDeviceClass.DOOR,
	DEVICE_GARAGE_DOOR_OPENING_DETECTOR: BinarySensorDeviceClass.GARAGE_DOOR,
	DEVICE_FLOOD_DETECTOR: BinarySensorDeviceClass.MOISTURE,
	DEVICE_GAS_DETECTOR: BinarySensorDeviceClass.GAS,
	DEVICE_SMOKE_DETECTOR: BinarySensorDeviceClass.SMOKE,
	DEVICE_LOCK: BinarySensorDeviceClass.LOCK,
	DEVICE_TAMPER: BinarySensorDeviceClass.TAMPER,
}


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	@callback
	def add_entities() -> None:
		entities = []

		mapping = {
			EntityType.DEVICE_STATE: JablotronDeviceStateSensorEntity,
			EntityType.PROBLEM: JablotronProblemSensorEntity,
			EntityType.FIRE: JablotronFireSensorEntity,
			EntityType.LAN_CONNECTION: JablotronLanConnectionEntity,
			EntityType.GSM_SIGNAL: JablotronGsmSignalEntity,
		}

		for entity_type, entity_class in mapping.items():
			for entity in jablotron_instance.entities[entity_type].values():
				if entity.id not in jablotron_instance.hass_entities:
					entities.append(entity_class(jablotron_instance, entity))

		async_add_entities(entities)

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)

	add_entities()


class JablotronBinarySensor(JablotronEntity, BinarySensorEntity):

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON


class JablotronProblemSensorEntity(JablotronBinarySensor):

	_attr_device_class = BinarySensorDeviceClass.PROBLEM


class JablotronFireSensorEntity(JablotronBinarySensor):

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_icon = "mdi:fire" if self._attr_is_on else "mdi:fire-off"


class JablotronDeviceStateSensorEntity(JablotronBinarySensor):

	_control: JablotronDevice

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronDevice,
	) -> None:

		self._attr_device_class = DEVICE_CLASSES[control.type] if control.type in DEVICE_CLASSES else None

		super().__init__(jablotron, control)

	def _update_attributes(self) -> None:
		super()._update_attributes()

		if self._control.type == DEVICE_GLASS_BREAK_DETECTOR:
			self._attr_icon = "mdi:image-broken-variant" if self._attr_is_on else "mdi:square-outline"
		elif self._control.type in (DEVICE_KEY_FOB, DEVICE_BUTTON):
			self._attr_icon = "mdi:gesture-double-tap" if self._attr_is_on else "mdi:circle-double"
		elif self._control.type == DEVICE_SIREN_INDOOR:
			self._attr_icon = "mdi:gesture-tap-box" if self._attr_is_on else "mdi:circle-box-outline"
		elif self._control.type == DEVICE_THERMOSTAT:
			self._attr_icon = "mdi:thermometer" if self._attr_is_on else "mdi:thermometer-off"


class JablotronLanConnectionEntity(JablotronBinarySensor):

	_attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
	_attr_entity_category = EntityCategory.DIAGNOSTIC


class JablotronGsmSignalEntity(JablotronBinarySensor):

	_attr_device_class = BinarySensorDeviceClass.CONNECTIVITY
	_attr_entity_category = EntityCategory.DIAGNOSTIC

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_icon = "mdi:signal" if self._attr_is_on else "mdi:signal-off"
