from __future__ import annotations

from enum import StrEnum
from pathlib import Path
import sys
from types import ModuleType


try:
	import homeassistant
except ModuleNotFoundError:
	homeassistant = ModuleType("homeassistant")
	core = ModuleType("homeassistant.core")
	const = ModuleType("homeassistant.const")
	components = ModuleType("homeassistant.components")
	alarm_control_panel = ModuleType("homeassistant.components.alarm_control_panel")
	exceptions = ModuleType("homeassistant.exceptions")
	helpers = ModuleType("homeassistant.helpers")
	storage = ModuleType("homeassistant.helpers.storage")
	dispatcher = ModuleType("homeassistant.helpers.dispatcher")
	device_registry = ModuleType("homeassistant.helpers.device_registry")
	entity = ModuleType("homeassistant.helpers.entity")
	event = ModuleType("homeassistant.helpers.event")
	typing = ModuleType("homeassistant.helpers.typing")
	entity_registry = ModuleType("homeassistant.helpers.entity_registry")

	class AlarmControlPanelState(StrEnum):
		PENDING = "pending"
		TRIGGERED = "triggered"

	class DeviceInfo(dict):
		def __init__(self, **kwargs):
			super().__init__(kwargs)

	class Entity:
		pass

	class EntityRegistry:
		pass

	class HomeAssistant:
		pass

	class HomeAssistantError(Exception):
		pass

	class Store:
		def __init__(self, *args, **kwargs):
			pass

	core.HomeAssistant = HomeAssistant
	core.callback = lambda function: function
	const.ATTR_BATTERY_LEVEL = "battery_level"
	const.CONF_PASSWORD = "password"
	const.EVENT_HOMEASSISTANT_STOP = "homeassistant_stop"
	const.STATE_OFF = "off"
	const.STATE_ON = "on"
	alarm_control_panel.AlarmControlPanelState = AlarmControlPanelState
	exceptions.HomeAssistantError = HomeAssistantError
	storage.Store = Store
	dispatcher.async_dispatcher_send = lambda *args, **kwargs: None
	dispatcher.dispatcher_send = lambda *args, **kwargs: None
	device_registry.async_get = lambda *args, **kwargs: None
	entity.DeviceInfo = DeviceInfo
	entity.Entity = Entity
	event.async_call_later = lambda *args, **kwargs: None
	typing.StateType = bool | float | int | str | None
	entity_registry.EntityRegistry = EntityRegistry
	entity_registry.async_get = lambda *args, **kwargs: None

	homeassistant.core = core
	homeassistant.const = const
	homeassistant.components = components
	homeassistant.helpers = helpers
	components.alarm_control_panel = alarm_control_panel
	helpers.storage = storage
	helpers.device_registry = device_registry
	helpers.entity_registry = entity_registry

	sys.modules.update({
		"homeassistant": homeassistant,
		"homeassistant.core": core,
		"homeassistant.const": const,
		"homeassistant.components": components,
		"homeassistant.components.alarm_control_panel": alarm_control_panel,
		"homeassistant.exceptions": exceptions,
		"homeassistant.helpers": helpers,
		"homeassistant.helpers.storage": storage,
		"homeassistant.helpers.dispatcher": dispatcher,
		"homeassistant.helpers.device_registry": device_registry,
		"homeassistant.helpers.entity": entity,
		"homeassistant.helpers.event": event,
		"homeassistant.helpers.typing": typing,
		"homeassistant.helpers.entity_registry": entity_registry,
	})

	integration_package = ModuleType("custom_components.jablotron100")
	integration_package.__path__ = [
		str(Path(__file__).parents[1] / "custom_components" / "jablotron100")
	]
	sys.modules["custom_components.jablotron100"] = integration_package
