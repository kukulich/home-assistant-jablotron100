"""The Jablotron integration."""

from homeassistant import config_entries, core
from homeassistant.const import Platform
from homeassistant.helpers import device_registry as dr
from homeassistant.helpers import entity_registry as er

from .const import (
	DATA_JABLOTRON,
	DATA_OPTIONS_UPDATE_UNSUBSCRIBER,
	DOMAIN,
)
from .jablotron import Jablotron


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> bool:
	hass.data.setdefault(DOMAIN, {})

	jablotron_instance: Jablotron = Jablotron(hass, config_entry.data, config_entry.options)
	await jablotron_instance.initialize()

	hass.data[DOMAIN][config_entry.entry_id] = {
		DATA_JABLOTRON: jablotron_instance,
		DATA_OPTIONS_UPDATE_UNSUBSCRIBER: config_entry.add_update_listener(options_update_listener),
	}

	central_unit = jablotron_instance.central_unit()

	if central_unit.model in ("JA-103K", "JA-103KRY", "JA-107K"):
		entity_registry = await er.async_get_registry(hass)
		not_working_gsm_signal_entity_id = entity_registry.async_get_entity_id(
			Platform.BINARY_SENSOR,
			DOMAIN,
			"{}.{}.gsm_signal_sensor".format(DOMAIN, central_unit.serial_port),
		)
		if not_working_gsm_signal_entity_id is not None:
			entity_registry.async_remove(not_working_gsm_signal_entity_id)

		not_working_gsm_signal_strength_entity_id = entity_registry.async_get_entity_id(
			Platform.SENSOR,
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

	for platform in (Platform.ALARM_CONTROL_PANEL, Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH):
		hass.async_create_task(
			hass.config_entries.async_forward_entry_setup(config_entry, platform)
		)

	return True


async def async_unload_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> bool:
	options_update_unsubscriber = hass.data[DOMAIN][config_entry.entry_id][DATA_OPTIONS_UPDATE_UNSUBSCRIBER]
	options_update_unsubscriber()

	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]
	jablotron_instance.shutdown()

	return True


async def options_update_listener(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]
	jablotron_instance.update_options(config_entry.options)
