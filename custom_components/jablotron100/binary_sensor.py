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
from .jablotron import JablotronEntity
from typing import Optional


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


class JablotronProblemSensorEntity(JablotronEntity, BinarySensorEntity):

	@property
	def is_on(self) -> bool:
		return self._state == STATE_ON

	@property
	def device_class(self) -> str:
		return DEVICE_CLASS_PROBLEM


class JablotronDeviceSensorEntity(JablotronEntity, BinarySensorEntity):

	@property
	def is_on(self) -> bool:
		return self._state == STATE_ON

	@property
	def icon(self) -> Optional[str]:
		if self._control.type == DEVICE_GLASS_BREAK_DETECTOR:
			return "mdi:image-broken-variant" if self._state == STATE_ON else "mdi:square-outline"

		if self._control.type in [DEVICE_KEY_FOB, DEVICE_BUTTON]:
			return "mdi:gesture-double-tap" if self._state == STATE_ON else "mdi:circle-double"

		if self._control.type == DEVICE_SIREN_INDOOR:
			return "mdi:gesture-tap-box" if self._state == STATE_ON else "mdi:circle-box-outline"

		if self._control.type == DEVICE_THERMOSTAT:
			return "mdi:thermometer" if self._state == STATE_ON else "mdi:thermometer-off"

		return None

	@property
	def device_class(self) -> Optional[str]:
		if self._control.type == DEVICE_MOTION_DETECTOR:
			return DEVICE_CLASS_MOTION

		if self._control.type == DEVICE_WINDOW_OPENING_DETECTOR:
			return DEVICE_CLASS_WINDOW

		if self._control.type == DEVICE_DOOR_OPENING_DETECTOR:
			return DEVICE_CLASS_DOOR

		if self._control.type == DEVICE_GARAGE_DOOR_OPENING_DETECTOR:
			return DEVICE_CLASS_GARAGE_DOOR

		if self._control.type == DEVICE_FLOOD_DETECTOR:
			return DEVICE_CLASS_MOISTURE

		if self._control.type == DEVICE_GAS_DETECTOR:
			return DEVICE_CLASS_GAS

		if self._control.type == DEVICE_SMOKE_DETECTOR:
			return DEVICE_CLASS_SMOKE

		if self._control.type == DEVICE_LOCK:
			return DEVICE_CLASS_LOCK

		return None


class JablotronLanConnectionEntity(JablotronEntity, BinarySensorEntity):

	@property
	def is_on(self) -> bool:
		return self._state == STATE_ON

	@property
	def device_class(self) -> str:
		return DEVICE_CLASS_CONNECTIVITY


class JablotronGsmSignalEntity(JablotronEntity, BinarySensorEntity):

	@property
	def is_on(self) -> bool:
		return self._state == STATE_ON

	@property
	def icon(self) -> Optional[str]:
		return "mdi:signal" if self._state == STATE_ON else "mdi:signal-off"

	@property
	def device_class(self) -> None:
		return DEVICE_CLASS_CONNECTIVITY

