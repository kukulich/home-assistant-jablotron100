"""The Jablotron integration."""

from homeassistant.const import Platform
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry as dr, storage
from typing import Final

from .const import (
	CONF_SERIAL_PORT,
	CONF_UNIQUE_ID,
	DOMAIN,
)
from .jablotron import Jablotron, STORAGE_VERSION


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
		model=central_unit.model,
		manufacturer="Jablotron",
		hw_version=central_unit.hardware_version,
		sw_version=central_unit.firmware_version,
	)

	await hass.config_entries.async_forward_entry_setups(config_entry, PLATFORMS)

	return True


async def async_unload_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry) -> bool:
	await hass.config_entries.async_unload_platforms(config_entry, PLATFORMS)

	# Only stop the running instance. Stored data must be preserved so reloads
	# (e.g. after changing options) do not have to re-detect every device.
	config_entry.runtime_data.shutdown()

	return True


async def async_remove_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry) -> None:
	"""Remove the integration's persisted data when the user deletes the entry."""
	unique_id = config_entry.data.get(CONF_UNIQUE_ID, config_entry.data.get(CONF_SERIAL_PORT))
	if unique_id is None:
		return

	store: storage.Store = storage.Store(hass, STORAGE_VERSION, DOMAIN)
	stored_data = await store.async_load()
	if not stored_data or unique_id not in stored_data:
		return

	del stored_data[unique_id]
	await store.async_save(stored_data)


async def options_update_listener(hass: HomeAssistant, config_entry: JablotronConfigEntry) -> None:
	await hass.config_entries.async_reload(config_entry.entry_id)
