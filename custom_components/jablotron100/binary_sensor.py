from __future__ import annotations
from homeassistant import config_entries, core
from homeassistant.components.binary_sensor import (
	BinarySensorEntity,
	DEVICE_CLASS_CONNECTIVITY,
	DEVICE_CLASS_DOOR,
	DEVICE_CLASS_GARAGE_DOOR,
	DEVICE_CLASS_GAS,
	DEVICE_CLASS_LOCK,
	DEVICE_CLASS_MOISTURE,
	DEVICE_CLASS_MOTION,
	DEVICE_CLASS_PROBLEM,
	DEVICE_CLASS_SMOKE,
	DEVICE_CLASS_WINDOW,
)
from homeassistant.const import STATE_ON
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
	DOMAIN,
)
from .jablotron import Jablotron, JablotronDevice, JablotronEntity


def get_control_device_class(control: JablotronDevice) -> str | None:
	if control.type == DEVICE_MOTION_DETECTOR:
		return DEVICE_CLASS_MOTION

	if control.type == DEVICE_WINDOW_OPENING_DETECTOR:
		return DEVICE_CLASS_WINDOW

	if control.type == DEVICE_DOOR_OPENING_DETECTOR:
		return DEVICE_CLASS_DOOR

	if control.type == DEVICE_GARAGE_DOOR_OPENING_DETECTOR:
		return DEVICE_CLASS_GARAGE_DOOR

	if control.type == DEVICE_FLOOD_DETECTOR:
		return DEVICE_CLASS_MOISTURE

	if control.type == DEVICE_GAS_DETECTOR:
		return DEVICE_CLASS_GAS

	if control.type == DEVICE_SMOKE_DETECTOR:
		return DEVICE_CLASS_SMOKE

	if control.type == DEVICE_LOCK:
		return DEVICE_CLASS_LOCK

	return None


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronDeviceSensorEntity(jablotron, control) for control in jablotron.device_sensors()))

	async_add_entities((JablotronProblemSensorEntity(jablotron, control) for control in jablotron.section_problem_sensors()))
	async_add_entities((JablotronProblemSensorEntity(jablotron, control) for control in jablotron.device_problem_sensors()))

	lan_connection = jablotron.lan_connection()
	if lan_connection is not None:
		async_add_entities([JablotronLanConnectionEntity(jablotron, lan_connection)])

	gsm_signal_sensor = jablotron.gsm_signal_sensor()
	if gsm_signal_sensor is not None:
		async_add_entities([JablotronGsmSignalEntity(jablotron, gsm_signal_sensor)])


class JablotronBinarySensor(JablotronEntity, BinarySensorEntity):

	def _update_attributes(self) -> None:
		self._attr_is_on = self._get_state() == STATE_ON


class JablotronProblemSensorEntity(JablotronBinarySensor):

	_attr_device_class = DEVICE_CLASS_PROBLEM


class JablotronDeviceSensorEntity(JablotronBinarySensor):

	_control: JablotronDevice

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronDevice,
	) -> None:
		self._attr_device_class = get_control_device_class(control)

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

	_attr_device_class = DEVICE_CLASS_CONNECTIVITY


class JablotronGsmSignalEntity(JablotronBinarySensor):

	_attr_device_class = DEVICE_CLASS_CONNECTIVITY

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_icon = "mdi:signal" if self._attr_is_on else "mdi:signal-off"
