from __future__ import annotations
from homeassistant import config_entries, core
from homeassistant.components.binary_sensor import (
	BinarySensorDeviceClass,
	BinarySensorEntity,
)
from homeassistant.helpers.entity import EntityCategory
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


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronDeviceSensorEntity(jablotron_instance, control) for control in jablotron_instance.device_sensors()))

	async_add_entities((JablotronProblemSensorEntity(jablotron_instance, control) for control in jablotron_instance.section_problem_sensors()))
	async_add_entities((JablotronProblemSensorEntity(jablotron_instance, control) for control in jablotron_instance.device_problem_sensors()))

	lan_connection = jablotron_instance.lan_connection()
	if lan_connection is not None:
		async_add_entities([JablotronLanConnectionEntity(jablotron_instance, lan_connection)])

	gsm_signal_sensor = jablotron_instance.gsm_signal_sensor()
	if gsm_signal_sensor is not None:
		async_add_entities([JablotronGsmSignalEntity(jablotron_instance, gsm_signal_sensor)])


class JablotronBinarySensor(JablotronEntity, BinarySensorEntity):

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON


class JablotronProblemSensorEntity(JablotronBinarySensor):

	_attr_device_class = BinarySensorDeviceClass.PROBLEM
	_attr_entity_category = EntityCategory.DIAGNOSTIC


class JablotronDeviceSensorEntity(JablotronBinarySensor):

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
