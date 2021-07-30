"""The Jablotron integration."""

from homeassistant import config_entries, core
from homeassistant.components.alarm_control_panel import DOMAIN as PLATFORM_ALARM_CONTROL_PANEL
from homeassistant.components.binary_sensor import DOMAIN as PLATFORM_BINARY_SENSOR
from homeassistant.components.sensor import DOMAIN as PLATFORM_SENSOR
from homeassistant.components.switch import DOMAIN as PLATFORM_SWITCH
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import (
	DATA_JABLOTRON,
	DATA_OPTIONS_UPDATE_UNSUBSCRIBER,
	DOMAIN,
)
from .jablotron import Jablotron


async def async_setup(hass: core.HomeAssistant, config: core.Config) -> bool:
	"""YAML configuration is not supported."""
	return True


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> bool:
	hass.data.setdefault(DOMAIN, {})

	jablotron = Jablotron(hass, config_entry.data, config_entry.options)
	await jablotron.initialize()

	hass.data[DOMAIN][config_entry.entry_id] = {
		DATA_JABLOTRON: jablotron,
		DATA_OPTIONS_UPDATE_UNSUBSCRIBER: config_entry.add_update_listener(options_update_listener),
	}

	central_unit = jablotron.central_unit()

	if central_unit.model in ("JA-103K", "JA-103KRY", "JA-107K"):
		entity_registry = await er.async_get_registry(hass)
		not_working_gsm_signal_entity_id = entity_registry.async_get_entity_id(
			PLATFORM_BINARY_SENSOR,
			DOMAIN,
			"{}.{}.gsm_signal_sensor".format(DOMAIN, central_unit.serial_port),
		)
		if not_working_gsm_signal_entity_id is not None:
			entity_registry.async_remove(not_working_gsm_signal_entity_id)

		not_working_gsm_signal_strength_entity_id = entity_registry.async_get_entity_id(
			PLATFORM_SENSOR,
			DOMAIN,
			"{}.{}.gsm_signal_strength_sensor".format(DOMAIN, central_unit.serial_port),
		)
		if not_working_gsm_signal_strength_entity_id is not None:
			entity_registry.async_remove(not_working_gsm_signal_strength_entity_id)

	device_registry = await dr.async_get_registry(hass)

	device_registry.async_get_or_create(
		config_entry_id=config_entry.entry_id,
		identifiers={(DOMAIN, central_unit.serial_port)},
		name="Jablotron 100",
		model="{} ({})".format(central_unit.model, central_unit.hardware_version),
		manufacturer="Jablotron",
		sw_version=central_unit.firmware_version,
	)

	for platform in (PLATFORM_ALARM_CONTROL_PANEL, PLATFORM_BINARY_SENSOR, PLATFORM_SENSOR, PLATFORM_SWITCH):
		hass.async_create_task(
			hass.config_entries.async_forward_entry_setup(config_entry, platform)
		)

	return True


async def async_unload_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> bool:
	options_update_unsubscriber = hass.data[DOMAIN][config_entry.entry_id][DATA_OPTIONS_UPDATE_UNSUBSCRIBER]
	options_update_unsubscriber()

	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]
	jablotron.shutdown()

	return True


async def options_update_listener(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]
	jablotron.update_options(config_entry.options)
