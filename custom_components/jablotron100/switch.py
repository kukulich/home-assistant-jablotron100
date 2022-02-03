from homeassistant import config_entries, core
from homeassistant.components.switch import (
	SwitchDeviceClass,
	SwitchEntity,
)
from homeassistant.const import STATE_ON, STATE_OFF
from .const import (
	DATA_JABLOTRON,
	DOMAIN,
)
from .jablotron import Jablotron, JablotronProgrammableOutput, JablotronEntity


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronProgrammableOutputEntity(jablotron_instance, control) for control in jablotron_instance.pg_outputs()))


class JablotronProgrammableOutputEntity(JablotronEntity, SwitchEntity):

	_control: JablotronProgrammableOutput
	_attr_device_class = SwitchDeviceClass.SWITCH

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronProgrammableOutput,
	) -> None:
		super().__init__(jablotron, control)

		self._update_attributes()

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_is_on = self._get_state() == STATE_ON

	async def async_turn_on(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_ON)
		self.update_state(STATE_ON)

	async def async_turn_off(self, **kwargs) -> None:
		self._jablotron.toggle_pg_output(self._control.pg_output_number, STATE_OFF)
		self.update_state(STATE_OFF)
