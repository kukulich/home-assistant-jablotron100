from __future__ import annotations
from homeassistant.components.event import (
	EventEntity,
	EventEntityDescription,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from typing import Dict
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
	EntityType,
	EventLoginType,
)
from .jablotron import Jablotron, JablotronControl, JablotronEntity

EVENT_TYPES: Dict[EntityType, EventEntityDescription] = {
	EntityType.EVENT_LOGIN: EventEntityDescription(
		key=EntityType.EVENT_LOGIN,
		translation_key="login",
		icon="mdi:login",
		event_types=[EventLoginType.WRONG_CODE.value],
	),
}


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	@callback
	def add_entities() -> None:
		entities = []

		for entity_type in EVENT_TYPES:
			for entity in jablotron_instance.entities[entity_type].values():
				if entity.id not in jablotron_instance.hass_entities:
					entities.append(JablotronEventEntity(jablotron_instance, entity, EVENT_TYPES[entity_type]))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class JablotronEventEntity(JablotronEntity, EventEntity):

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronControl,
		description: EventEntityDescription,
	) -> None:
		self.entity_description = description

		super().__init__(jablotron, control)

	def trigger_event(self, event: EventLoginType) -> None:
		self._trigger_event(event.value)
		self.async_write_ha_state()
