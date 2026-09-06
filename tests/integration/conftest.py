from __future__ import annotations

import logging
from types import MappingProxyType
from unittest.mock import patch

from homeassistant import loader
from homeassistant.config_entries import ConfigEntries, ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers import device_registry, entity_registry, frame
from homeassistant.helpers.entity_component import EntityComponent
import pytest
import pytest_asyncio

from custom_components.jablotron100.const import (
	CONF_DEVICES,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_SERIAL_PORT,
	CONF_UNIQUE_ID,
)
from custom_components.jablotron100.jablotron import Jablotron, JablotronCentralUnit
from homeassistant.const import CONF_PASSWORD


@pytest_asyncio.fixture
async def hass(tmp_path):
	instance = HomeAssistant(str(tmp_path))
	try:
		loader.async_setup(instance)
		frame.async_setup(instance)
		instance.config_entries = ConfigEntries(instance, {})
		instance.data[device_registry.DATA_REGISTRY] = device_registry.DeviceRegistry(instance)
		await device_registry.async_load(instance)
		await entity_registry.async_load(instance)
		yield instance
	finally:
		await instance.async_block_till_done()
		await instance.async_stop(force=True)


@pytest.fixture
def entity_component(hass):
	entry = ConfigEntry(
		entry_id="test-entry", domain="jablotron100", title="Test panel",
		data={}, options={}, source="user", unique_id="test-panel",
		version=1, minor_version=1, discovery_keys=MappingProxyType({}), subentries_data=None,
	)
	hass.config_entries._entries[entry.entry_id] = entry

	def create_component(domain):
		component = EntityComponent(logging.getLogger(__name__), domain, hass)
		component._platforms[domain].config_entry = entry
		component.register_shutdown()
		return component

	return create_component


@pytest.fixture(autouse=True)
def prevent_serial_io():
	with (
		patch("custom_components.jablotron100.jablotron.Jablotron._open_read_stream", side_effect=AssertionError("Unexpected serial read")),
		patch("custom_components.jablotron100.jablotron.Jablotron._open_write_stream", side_effect=AssertionError("Unexpected serial write")),
		patch("custom_components.jablotron100.config_flow.check_serial_port", side_effect=AssertionError("Unexpected serial probe")),
	):
		yield


@pytest.fixture
def jablotron(hass):
	instance = Jablotron(
		hass,
		"test-entry",
		{
			CONF_UNIQUE_ID: "test-panel",
			CONF_SERIAL_PORT: "/dev/jablotron-test-only",
			CONF_PASSWORD: "1234",
			CONF_NUMBER_OF_DEVICES: 0,
			CONF_NUMBER_OF_PG_OUTPUTS: 1,
			CONF_DEVICES: [],
		},
		{},
	)
	instance._central_unit = JablotronCentralUnit("test-panel", "JA-103K", "1", "1")
	instance.last_update_success = True
	return instance