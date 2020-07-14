from homeassistant import config_entries, core
from homeassistant.const import (
	STATE_ALARM_DISARMED,
	STATE_ALARM_ARMED_AWAY,
	STATE_ALARM_ARMED_NIGHT,
	STATE_ALARM_ARMING,
)
from homeassistant.components.alarm_control_panel import (
	AlarmControlPanelEntity,
	FORMAT_NUMBER,
	SUPPORT_ALARM_ARM_AWAY,
	SUPPORT_ALARM_ARM_NIGHT,
)
from typing import Optional
from .const import DATA_JABLOTRON, DOMAIN
from .jablotron import JablotronEntity, JablotronAlarmControlPanel, Jablotron


async def async_setup_entry(hass: core.HomeAssistant, config_entry: config_entries.ConfigEntry, async_add_entities) -> None:
	jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	async_add_entities((JablotronAlarmControlPanelEntity(jablotron, control) for control in jablotron.alarm_control_panels()), True)


class JablotronAlarmControlPanelEntity(JablotronEntity, AlarmControlPanelEntity):

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronAlarmControlPanel,
	) -> None:
		super().__init__(jablotron, control)

		self._arming_in_progress: bool = False

	@property
	def code_format(self) -> str:
		return FORMAT_NUMBER

	@property
	def supported_features(self) -> int:
		return SUPPORT_ALARM_ARM_AWAY | SUPPORT_ALARM_ARM_NIGHT

	def update_state(self, state: str) -> None:
		if self._arming_in_progress == True:
			if state == STATE_ALARM_DISARMED:
				# Ignore first update with DISARMED state because it's probably outdated
				return

			self._arming_in_progress = False

		super().update_state(state)

	async def async_alarm_disarm(self, code: Optional[str] = None) -> None:
		if code is None and self._jablotron.is_code_required_for_state(STATE_ALARM_DISARMED):
			return

		self._arming_in_progress = False
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_DISARMED, code)
		self.update_state(STATE_ALARM_DISARMED)

	async def async_alarm_arm_away(self, code: Optional[str] = None) -> None:
		if code is None and self._jablotron.is_code_required_for_state(STATE_ALARM_ARMED_AWAY):
			return

		self._arming_in_progress = True
		self.update_state(STATE_ALARM_ARMING)
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_ARMED_AWAY, code)

	async def async_alarm_arm_night(self, code: Optional[str] = None) -> None:
		if code is None and self._jablotron.is_code_required_for_state(STATE_ALARM_ARMED_NIGHT):
			return

		self._arming_in_progress = True
		self.update_state(STATE_ALARM_ARMING)
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_ARMED_NIGHT, code)
