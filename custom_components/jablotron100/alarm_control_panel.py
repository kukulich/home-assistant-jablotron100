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
from homeassistant.helpers.typing import StateType
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

		self._state_before_arming: Optional[str] = None

	@property
	def state(self) -> StateType:
		return self._state

	@property
	def code_format(self) -> Optional[str]:
		if self._state == STATE_ALARM_DISARMED:
			code_required = self._jablotron.is_code_required_for_arm()
		else:
			code_required = self._jablotron.is_code_required_for_disarm()

		return FORMAT_NUMBER if code_required is True else None

	@property
	def supported_features(self) -> int:
		return SUPPORT_ALARM_ARM_AWAY | SUPPORT_ALARM_ARM_NIGHT

	def update_state(self, state: str) -> None:
		state_before_arming = self._state_before_arming
		self._state_before_arming = None

		if self._state == STATE_ALARM_ARMING and state_before_arming == state:
			# Ignore first update because it's probably outdated
			return

		super().update_state(state)

	async def async_alarm_disarm(self, code: Optional[str] = None) -> None:
		if self._state == STATE_ALARM_DISARMED:
			return

		code = JablotronAlarmControlPanelEntity._clean_code(code)

		if code is None and self._jablotron.is_code_required_for_disarm():
			return

		self._state_before_arming = None
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_DISARMED, code)
		self.update_state(STATE_ALARM_DISARMED)

	async def async_alarm_arm_away(self, code: Optional[str] = None) -> None:
		if self._state == STATE_ALARM_ARMED_AWAY:
			return

		code = JablotronAlarmControlPanelEntity._clean_code(code)

		if code is None and self._jablotron.is_code_required_for_arm():
			return

		state_before_arming = self._state
		self.update_state(STATE_ALARM_ARMING)
		self._state_before_arming = state_before_arming
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_ARMED_AWAY, code)

	async def async_alarm_arm_night(self, code: Optional[str] = None) -> None:
		if self._state == STATE_ALARM_ARMED_NIGHT or self._state == STATE_ALARM_ARMED_AWAY:
			return

		code = JablotronAlarmControlPanelEntity._clean_code(code)

		if code is None and self._jablotron.is_code_required_for_arm():
			return

		state_before_arming = self._state
		self.update_state(STATE_ALARM_ARMING)
		self._state_before_arming = state_before_arming
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_ARMED_NIGHT, code)

	@staticmethod
	def _clean_code(code: Optional[str]) -> Optional[str]:
		return None if code == "" else code
