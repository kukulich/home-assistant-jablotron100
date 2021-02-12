from homeassistant import config_entries, core
from homeassistant.components.switch import DEVICE_CLASS_SWITCH, SwitchEntity
from homeassistant.const import STATE_ON, STATE_OFF
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
)
from .jablotron import Jablotron, JablotronProgrammableOutput, JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronProgrammableOutputEntity(jablotron, control) for control in jablotron.pg_outputs()))


class JablotronProgrammableOutputEntity(JablotronEntity, SwitchEntity):

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronProgrammableOutput,
	) -> None:
		super().__init__(jablotron, control)

	@property
	def is_on(self) -> bool:
		return self._state == STATE_ON

	@property
	def device_class(self):
		return DEVICE_CLASS_SWITCH

	async def async_turn_on(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_ON)
		self.update_state(STATE_ON)

	async def async_turn_off(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_OFF)
		self.update_state(STATE_OFF)
