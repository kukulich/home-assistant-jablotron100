from __future__ import annotations

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import HomeAssistant
from .const import CONF_DEVICES, DOMAIN, DATA_JABLOTRON
from .jablotron import Jablotron


async def async_get_config_entry_diagnostics(
	hass: HomeAssistant, config_entry: ConfigEntry
) -> dict:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	configuration = async_redact_data(config_entry.data, CONF_PASSWORD)
	del configuration[CONF_DEVICES]

	central_unit = jablotron_instance.central_unit()

	devices = []
	device_number = 1
	for device_type in config_entry.data[CONF_DEVICES]:
		devices.append({
			"number": device_number,
			"type": device_type,
			"section": jablotron_instance.get_device_section(device_number),
			"wireless": jablotron_instance.is_wireless_device(device_number),
			"battery": jablotron_instance.is_device_with_battery(device_number),
		})

		device_number += 1

	return {
		"central_unit": {
			"model": central_unit.model,
			"firmware_version": central_unit.firmware_version,
			"hardware_version": central_unit.hardware_version,
			"battery": jablotron_instance.is_central_unit_with_battery(),
			"buses": jablotron_instance.get_central_unit_buses(),
		},
		"configuration": configuration,
		"options": dict(config_entry.options),
		"devices": devices,
	}
