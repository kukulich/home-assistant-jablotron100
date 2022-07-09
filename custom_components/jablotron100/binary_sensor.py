from __future__ import annotations
from homeassistant.components.binary_sensor import (
	BinarySensorDeviceClass,
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

from typing import Final
from .const import (
	DATA_JABLOTRON,
	DeviceType,
	DOMAIN,
	EntityType,
)
from .jablotron import Jablotron, JablotronDevice, JablotronEntity

DEVICE_CLASSES: Final = {
	DeviceType.MOTION_DETECTOR: BinarySensorDeviceClass.MOTION,
	DeviceType.WINDOW_OPENING_DETECTOR: BinarySensorDeviceClass.WINDOW,
	DeviceType.DOOR_OPENING_DETECTOR: BinarySensorDeviceClass.DOOR,
	DeviceType.GARAGE_DOOR_OPENING_DETECTOR: BinarySensorDeviceClass.GARAGE_DOOR,
	DeviceType.FLOOD_DETECTOR: BinarySensorDeviceClass.MOISTURE,
	DeviceType.GAS_DETECTOR: BinarySensorDeviceClass.GAS,
	DeviceType.SMOKE_DETECTOR: BinarySensorDeviceClass.SMOKE,
	DeviceType.LOCK: BinarySensorDeviceClass.LOCK,
	DeviceType.TAMPER: BinarySensorDeviceClass.TAMPER,
}

DEVICE_SENSOR_NAMES: Final = {
	DeviceType.MOTION_DETECTOR: "Motion",
	DeviceType.WINDOW_OPENING_DETECTOR: "Window",
	DeviceType.DOOR_OPENING_DETECTOR: "Door",
	DeviceType.GARAGE_DOOR_OPENING_DETECTOR: "Garage door",
	DeviceType.GLASS_BREAK_DETECTOR: "Glass",
	DeviceType.FLOOD_DETECTOR: "Moisture",
	DeviceType.GAS_DETECTOR: "Gas",
	DeviceType.SMOKE_DETECTOR: "Smoke",
	DeviceType.LOCK: "Lock",
	DeviceType.TAMPER: "Tamper",
	DeviceType.THERMOSTAT: "Thermostat",
	DeviceType.THERMOMETER: "Thermometer",
	DeviceType.SIREN_INDOOR: "Button",
	DeviceType.BUTTON: "Button",
	DeviceType.KEY_FOB: "Button",
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

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON


class JablotronProblemSensorEntity(JablotronBinarySensor):

	_attr_device_class = BinarySensorDeviceClass.PROBLEM
	_attr_entity_category = EntityCategory.DIAGNOSTIC


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

		super().__init__(jablotron, control)

		self._attr_device_class = DEVICE_CLASSES[control.type] if control.type in DEVICE_CLASSES else None
		self._attr_name = DEVICE_SENSOR_NAMES[control.type] if control.type in DEVICE_SENSOR_NAMES else "State"

	def _update_attributes(self) -> None:
		super()._update_attributes()

		if self._control.type == DeviceType.GLASS_BREAK_DETECTOR:
			self._attr_icon = "mdi:image-broken-variant" if self._attr_is_on else "mdi:square-outline"
		elif self._control.type in (DeviceType.KEY_FOB, DeviceType.BUTTON):
			self._attr_icon = "mdi:gesture-double-tap" if self._attr_is_on else "mdi:circle-double"
		elif self._control.type == DeviceType.SIREN_INDOOR:
			self._attr_icon = "mdi:gesture-tap-box" if self._attr_is_on else "mdi:circle-box-outline"
		elif self._control.type == DeviceType.THERMOSTAT:
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
