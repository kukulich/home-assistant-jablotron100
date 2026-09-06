from __future__ import annotations

import asyncio
from types import MappingProxyType
from unittest.mock import patch

import homeassistant
import pytest


pytestmark = pytest.mark.skipif(
	not getattr(homeassistant, "__file__", None),
	reason="Device parent registry tests require an installed Home Assistant",
)


@pytest.mark.parametrize("shared_identifier", [False, True])
def test_setup_registers_parent_before_platforms_and_scopes_lookup(tmp_path, shared_identifier):
	from homeassistant import loader
	from homeassistant.config_entries import ConfigEntries, ConfigEntry
	from homeassistant.core import HomeAssistant
	from homeassistant.helpers import device_registry as dr, frame

	from custom_components.jablotron100 import PLATFORMS, async_setup_entry
	from custom_components.jablotron100.const import DOMAIN
	from custom_components.jablotron100.jablotron import (
		Jablotron,
		JablotronCentralUnit,
		JablotronControl,
		JablotronEntity,
		JablotronHassDevice,
	)

	async def run_scenario():
		hass = HomeAssistant(str(tmp_path))
		try:
			loader.async_setup(hass)
			frame.async_setup(hass)
			hass.config_entries = ConfigEntries(hass, {})
			hass.data[dr.DATA_REGISTRY] = dr.DeviceRegistry(hass)
			await dr.async_load(hass)
			registry = dr.async_get(hass)
			parents = []
			peripherals = []

			async def initialize(instance):
				identifier = "shared-panel" if shared_identifier else instance._config_entry_id
				instance._central_unit = JablotronCentralUnit(identifier, "JA-103K", "1", "1")

			async def forward_platforms(entry, platforms):
				assert platforms == PLATFORMS
				instance = entry.runtime_data
				central_unit = instance.central_unit()
				parent = registry.async_get_device_by_identifier((DOMAIN, central_unit.unique_id), entry.entry_id)
				assert parent is not None
				parents.append(parent)
				control = JablotronControl(
					central_unit,
					JablotronHassDevice("device_1", "Door", "device", {"number": "1"}),
					"device_1_state",
				)
				entity = JablotronEntity(instance, control)
				assert entity.device_info["via_device_id"] == parent.id
				assert "via_device" not in entity.device_info
				assert entity.device_info["identifiers"] == {(DOMAIN, "device_1")}
				peripheral = registry.async_get_or_create(config_entry_id=entry.entry_id, **entity.device_info)
				assert peripheral.via_device_id == parent.id
				peripherals.append(peripheral)
				central_entity = JablotronEntity(instance, JablotronControl(central_unit, None, "central_problem"))
				assert "via_device_id" not in central_entity.device_info

			with (
				patch.object(Jablotron, "initialize", initialize),
				patch.object(hass.config_entries, "async_forward_entry_setups", side_effect=forward_platforms) as forward,
			):
				for entry_id in ("panel-a", "panel-b"):
					entry = ConfigEntry(
						entry_id=entry_id, domain=DOMAIN, title=entry_id,
						data={}, options={}, source="user", unique_id=entry_id,
						version=1, minor_version=1, discovery_keys=MappingProxyType({}), subentries_data=None,
					)
					hass.config_entries._entries[entry.entry_id] = entry
					assert await async_setup_entry(hass, entry)
				assert forward.await_count == 2

			assert parents[0].id != parents[1].id
			assert peripherals[0].id != peripherals[1].id
			assert peripherals[0].via_device_id != peripherals[1].via_device_id
		finally:
			await hass.async_block_till_done()
			await hass.async_stop(force=True)

	asyncio.run(run_scenario())