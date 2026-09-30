from __future__ import annotations

import asyncio
from types import MappingProxyType
from unittest.mock import patch

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import STATE_OFF
from homeassistant.helpers import device_registry as dr
import pytest

from custom_components.jablotron100.binary_sensor import BINARY_SENSOR_TYPES, JablotronBinarySensor
from custom_components.jablotron100.const import (
	CONF_DEVICES, CONF_NUMBER_OF_DEVICES, CONF_UNIQUE_ID, DOMAIN,
	DeviceConnection, DeviceData, DeviceType, EntityType,
)
from custom_components.jablotron100.jablotron import (
	Jablotron, JablotronCentralUnit, JablotronControl, JablotronEntity,
	STORAGE_VERSION,
)
from custom_components.jablotron100.storage import JablotronStore


pytestmark = pytest.mark.asyncio

IDENTIFICATION_PACKET = bytes.fromhex(
	"9021134008084c5736323130334009094c573132313036614009024a412d3135315354"
)
EXPECTED = {"model": "JA-151ST", "hw_version": "LW62103", "sw_version": "LW12106a"}


@pytest.fixture
def peripheral(hass, jablotron, entity_component):
	component = entity_component("binary_sensor")
	jablotron._config.update({
		CONF_NUMBER_OF_DEVICES: 19,
		CONF_DEVICES: [DeviceType.EMPTY] * 18 + [DeviceType.SMOKE_DETECTOR],
	})
	jablotron._devices_data = {
		"device_19": {
			DeviceData.CONNECTION: DeviceConnection.WIRED,
			DeviceData.SIGNAL_STRENGTH: None,
			DeviceData.BATTERY: True,
			DeviceData.BATTERY_LEVEL: 100,
			DeviceData.SECTION: 1,
		},
	}
	registry = dr.async_get(hass)
	parent = registry.async_get_or_create(
		config_entry_id=jablotron._config_entry_id,
		identifiers={(DOMAIN, jablotron.central_unit().unique_id)},
		model="JA-103K",
	)
	return jablotron, component, registry, parent


def create_entities(instance):
	hass_device = instance._create_device_hass_device(19)
	instance._device_hass_devices[hass_device.id] = hass_device
	entities = []
	for entity_type, control_id in ((EntityType.PROBLEM, "problem_19"), (EntityType.DEVICE_STATE_SMOKE, "smoke_19")):
		control = JablotronControl(instance.central_unit(), hass_device, control_id)
		instance.entities_states[control_id] = STATE_OFF
		entity = JablotronBinarySensor(instance, control, BINARY_SENSOR_TYPES[entity_type])
		entity.entity_id = f"binary_sensor.metadata_{control_id}"
		entities.append(entity)
	return entities


async def receive(hass, instance, packet=IDENTIFICATION_PACKET):
	await hass.async_add_executor_job(instance._parse_device_info_packet, packet)
	await hass.async_block_till_done()


async def test_live_metadata_updates_all_entities_and_registry(hass, peripheral):
	instance, component, registry, parent = peripheral
	entities = create_entities(instance)
	try:
		await component.async_add_entities(entities)
		before = registry.async_get_device_by_identifier((DOMAIN, "device_19"), instance._config_entry_id)
		assert before is not None
		assert all(entity.device_info.get(key) is None for entity in entities for key in EXPECTED)
		apply_registry_update = registry.async_update_device

		def update_on_loop(*args, **kwargs):
			assert asyncio.get_running_loop() is hass.loop
			return apply_registry_update(*args, **kwargs)

		with (
			patch.object(instance, "_store_devices_data", wraps=instance._store_devices_data) as store,
			patch.object(registry, "async_update_device", side_effect=update_on_loop) as update,
		):
			await receive(hass, instance)
			await receive(hass, instance)
			store.assert_called_once_with()
			update.assert_called_once()

		for entity in entities:
			assert {key: entity.device_info[key] for key in EXPECTED} == EXPECTED
			assert entity.device_info["via_device_id"] == parent.id
			assert entity.device_info["identifiers"] == {(DOMAIN, "device_19")}
			assert hass.states.get(entity.entity_id).state == STATE_OFF
		current = registry.async_get(before.id)
		assert (current.model, current.hw_version, current.sw_version) == tuple(EXPECTED.values())
		assert current.via_device_id == before.via_device_id == parent.id
		assert current.name == before.name

		update_packet = Jablotron.create_packet(b"\x90", bytes.fromhex("13400309563240020200400210ff400202ff"))
		with patch.object(Jablotron, "_log_error_with_packet") as log_error:
			await receive(hass, instance, update_packet)
			log_error.assert_called_once_with("Invalid device identification text", update_packet)
		current = registry.async_get(before.id)
		assert (current.model, current.hw_version, current.sw_version) == ("JA-151ST", "LW62103", "V2")
		assert all(entity.device_info["sw_version"] == "V2" for entity in entities)
	finally:
		for entity in entities:
			await entity.async_remove()


async def test_metadata_before_registration_and_after_storage_reload(hass, peripheral):
	instance, component, registry, parent = peripheral
	await receive(hass, instance)
	assert registry.async_get_device_by_identifier((DOMAIN, "device_19"), instance._config_entry_id) is None
	await instance._store.async_save(instance._data_to_store())

	restored = Jablotron(hass, instance._config_entry_id, instance._config, {})
	restored._central_unit = instance.central_unit()
	restored._store = JablotronStore(hass, STORAGE_VERSION)
	restored._stored_data = restored._store.data
	await restored._load_stored_data()
	assert restored._devices_data == instance._devices_data
	entities = create_entities(restored)
	try:
		await component.async_add_entities(entities)
		for entity in entities:
			assert {key: entity.device_info[key] for key in EXPECTED} == EXPECTED
		entry = registry.async_get_device_by_identifier((DOMAIN, "device_19"), restored._config_entry_id)
		assert (entry.model, entry.hw_version, entry.sw_version) == tuple(EXPECTED.values())
		assert entry.via_device_id == parent.id
	finally:
		for entity in entities:
			await entity.async_remove()


async def test_identification_does_not_skip_periodic_device_data(hass, peripheral):
	instance, _, _, _ = peripheral
	packet = bytes.fromhex("901313400210019c07052683160044211903c03000")
	with patch.object(instance, "_update_entity_state") as update:
		await receive(hass, instance, packet)
		assert [call.args for call in update.call_args_list] == [
			("device_battery_problem_sensor_19", "off"),
			("device_battery_level_sensor_19", 50),
			("device_temperature_sensor_19", 22.0),
		]
	assert DeviceData.MODEL not in instance._devices_data["device_19"]


@pytest.mark.parametrize("condition", ["ignored", "shutdown", "removed", "central", "unconfigured"])
async def test_identification_does_not_update_ineligible_device(hass, peripheral, condition):
	instance, _, _, _ = peripheral
	if condition == "ignored":
		instance._config[CONF_DEVICES][-1] = DeviceType.EMPTY
	elif condition == "shutdown":
		instance._stream_stop_event.set()
	elif condition == "removed":
		instance._devices_data.clear()
	packet = IDENTIFICATION_PACKET
	if condition in ("central", "unconfigured"):
		packet = packet[:2] + bytes([0 if condition == "central" else 20]) + packet[3:]
	with (
		patch.object(instance, "_store_devices_data") as store,
		patch.object(instance, "_log_error_with_packet") as log_error,
	):
		await receive(hass, instance, packet)
		store.assert_not_called()
		if condition in ("removed", "unconfigured"):
			log_error.assert_called_once()
		else:
			log_error.assert_not_called()


@pytest.mark.parametrize("condition", ["ignored", "shutdown", "unconfigured"])
async def test_queued_identification_respects_lifecycle_changes(hass, peripheral, condition):
	instance, _, _, _ = peripheral
	with patch.object(instance, "_store_devices_data") as store:
		instance._parse_device_info_packet(IDENTIFICATION_PACKET)
		if condition == "ignored":
			instance._config[CONF_DEVICES][-1] = DeviceType.EMPTY
		elif condition == "shutdown":
			instance._stream_stop_event.set()
		else:
			instance._config[CONF_NUMBER_OF_DEVICES] = 0
		await hass.async_block_till_done()
		store.assert_not_called()
	assert DeviceData.MODEL not in instance._devices_data["device_19"]


async def test_identification_is_isolated_between_panels(hass, peripheral):
	instance, component, registry, _ = peripheral
	other_entry = ConfigEntry(
		entry_id="other-entry", domain=DOMAIN, title="Other panel",
		data={}, options={}, source="user", unique_id="other-panel", version=1,
		minor_version=1, discovery_keys=MappingProxyType({}), subentries_data=None,
	)
	hass.config_entries._entries[other_entry.entry_id] = other_entry
	other = Jablotron(hass, other_entry.entry_id, {**instance._config, CONF_UNIQUE_ID: "other-panel"}, {})
	other._central_unit = JablotronCentralUnit("other-panel", "JA-103K", "1", "1")
	other._devices_data = {"device_19": {**instance._devices_data["device_19"], DeviceData.MODEL: "OTHER"}}
	other_parent = registry.async_get_or_create(
		config_entry_id=other_entry.entry_id, identifiers={(DOMAIN, "other-panel")},
	)
	other_device = other._create_device_hass_device(19)
	other._device_hass_devices[other_device.id] = other_device
	other_entity = JablotronEntity(other, JablotronControl(other.central_unit(), other_device, "other"))
	other.hass_entities["other"] = other_entity
	other_registry = registry.async_get_or_create(config_entry_id=other_entry.entry_id, **other_entity.device_info)
	entities = create_entities(instance)
	try:
		await component.async_add_entities(entities)
		await receive(hass, instance)
		assert registry.async_get(other_registry.id).model == "OTHER"
		assert registry.async_get(other_registry.id).via_device_id == other_parent.id
		assert other_entity.device_info["model"] == "OTHER"
		assert DeviceData.FIRMWARE_VERSION not in other._devices_data["device_19"]
		assert all(entity.device_info["model"] == "JA-151ST" for entity in entities)
		other_packet = Jablotron.create_packet(b"\x90", bytes.fromhex("134005024a412d59"))
		await receive(hass, other, other_packet)
		assert registry.async_get(other_registry.id).model == "JA-Y"
		assert all(entity.device_info["model"] == "JA-151ST" for entity in entities)
		assert instance._stored_data["test-panel"]["devices"]["device_19"][DeviceData.MODEL] == "JA-151ST"
		assert instance._stored_data["other-panel"]["devices"]["device_19"][DeviceData.MODEL] == "JA-Y"
	finally:
		for entity in entities:
			await entity.async_remove()
