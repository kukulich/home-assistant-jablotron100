"""The Jablotron integration."""

from homeassistant import config_entries, core
from homeassistant.components.alarm_control_panel import DOMAIN as PLATFORM_ALARM_CONTROL_PANEL
from homeassistant.components.binary_sensor import DOMAIN as PLATFORM_BINARY_SENSOR

from .const import (
	DATA_JABLOTRON,
	DATA_OPTIONS_UPDATE_UNSUBSCRIBER,
	DOMAIN,
	LOGGER,
)
from .jablotron import Jablotron


async def async_setup(hass: core.HomeAssistant, config: core.Config) -> bool:
	"""YAML configuration is not supported."""
	return True


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> bool:
	hass.data.setdefault(DOMAIN, {})

	jablotron = Jablotron(hass, config_entry.data, config_entry.options)
	jablotron.initialize()

	hass.data[DOMAIN][config_entry.entry_id] = {
		DATA_JABLOTRON: jablotron,
		DATA_OPTIONS_UPDATE_UNSUBSCRIBER: config_entry.add_update_listener(options_update_listener),
	}

	for platform in [PLATFORM_ALARM_CONTROL_PANEL, PLATFORM_BINARY_SENSOR]:
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
