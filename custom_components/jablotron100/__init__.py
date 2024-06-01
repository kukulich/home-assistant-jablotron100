"""The Jablotron integration."""

from homeassistant.const import Platform
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr
from typing import Final

from .const import (
	DOMAIN,
	LOGGER,
)
from .jablotron import Jablotron


type JablotronConfigEntry = ConfigEntry[Jablotron]

PLATFORMS: Final = [
	Platform.ALARM_CONTROL_PANEL,
	Platform.BINARY_SENSOR,
	Platform.EVENT,
	Platform.SENSOR,
	Platform.SWITCH
]


async def async_setup_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry) -> bool:
	hass.data.setdefault(DOMAIN, {})

	jablotron_instance: Jablotron = Jablotron(hass, config_entry.entry_id, config_entry.data, config_entry.options)
	await jablotron_instance.initialize()

	config_entry.runtime_data = jablotron_instance
	config_entry.async_on_unload(config_entry.add_update_listener(options_update_listener))

	central_unit = jablotron_instance.central_unit()
	device_registry = dr.async_get(hass)

	device_registry.async_get_or_create(
		config_entry_id=config_entry.entry_id,
		identifiers={(DOMAIN, central_unit.unique_id)},
		name="Jablotron 100",
		model="{} ({})".format(central_unit.model, central_unit.hardware_version),
		manufacturer="Jablotron",
		sw_version=central_unit.firmware_version,
	)

	await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

	return True


async def async_unload_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry) -> bool:
	await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)

	config_entry.runtime_data.shutdown_and_clean()

	return True


async def options_update_listener(hass: HomeAssistant, config_entry: JablotronConfigEntry) -> None:
	await hass.config_entries.async_reload(config_entry.entry_id)
