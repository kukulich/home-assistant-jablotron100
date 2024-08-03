from homeassistant.components.button import ButtonEntity
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from . import JablotronConfigEntry
from .const import EntityType
from .jablotron import Jablotron, JablotronEntity


async def async_setup_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = config_entry.runtime_data

	@callback
	def add_entities() -> None:
		entities = []

		for entity in jablotron_instance.entities[EntityType.DAY_NIGHT_MODE].values():
			if entity.id not in jablotron_instance.hass_entities:
				entities.append(JablotronDayNightModeEntity(jablotron_instance, entity))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class JablotronDayNightModeEntity(JablotronEntity, ButtonEntity):

	_attr_translation_key = "day_night_mode"
	_attr_icon = "mdi:theme-light-dark"

	def press(self) -> None:
		self._jablotron.toggle_day_night_mode()
