from __future__ import annotations
from homeassistant.const import (
	STATE_ALARM_DISARMED,
	STATE_ALARM_ARMED_AWAY,
	STATE_ALARM_ARMED_HOME,
	STATE_ALARM_ARMED_NIGHT,
)
from homeassistant.components.alarm_control_panel import (
	AlarmControlPanelEntity,
	AlarmControlPanelEntityFeature,
	CodeFormat,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType
from .const import DATA_JABLOTRON, DOMAIN, EntityType, PartiallyArmingMode
from .jablotron import Jablotron, JablotronEntity, JablotronAlarmControlPanel


async def async_setup_entry(hass: HomeAssistant, config_entry: ConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = hass.data[DOMAIN][config_entry.entry_id][DATA_JABLOTRON]

	@callback
	def add_entities() -> None:
		entities = []

		for entity in jablotron_instance.entities[EntityType.ALARM_CONTROL_PANEL].values():
			if entity.id not in jablotron_instance.hass_entities:
				entities.append(JablotronAlarmControlPanelEntity(jablotron_instance, entity))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class JablotronAlarmControlPanelEntity(JablotronEntity, AlarmControlPanelEntity):
	_control: JablotronAlarmControlPanel
	_changed_by: str | None = None

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronAlarmControlPanel,
	) -> None:
		super().__init__(jablotron, control)

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._attr_supported_features = self._detect_supported_features()
		self._attr_state = self._get_state()
		self._attr_changed_by = self._changed_by
		self._attr_code_format = self._detect_code_format()

	async def async_alarm_disarm(self, code: str | None = None) -> None:
		if self._get_state() == STATE_ALARM_DISARMED:
			return

		code = JablotronAlarmControlPanelEntity._clean_code(code)

		if code is None and self._jablotron.is_code_required_for_disarm():
			return

		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_DISARMED, code)

	async def async_alarm_arm_away(self, code: str | None = None) -> None:
		if self._get_state() == STATE_ALARM_ARMED_AWAY:
			return

		code = JablotronAlarmControlPanelEntity._clean_code(code)

		if code is None and self._jablotron.is_code_required_for_arm():
			return

		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, STATE_ALARM_ARMED_AWAY, code)

	async def async_alarm_arm_home(self, code: str | None = None) -> None:
		await self._arm_partially(STATE_ALARM_ARMED_HOME, code)

	async def async_alarm_arm_night(self, code: str | None = None) -> None:
		await self._arm_partially(STATE_ALARM_ARMED_NIGHT, code)

	def update_state(self, state: StateType) -> None:
		if self._get_state() != state:
			self._changed_by = "User {}".format(self._jablotron.last_active_user())

		super().update_state(state)

	async def _arm_partially(self, state: StateType, code: str | None = None) -> None:
		if self._get_state() in (STATE_ALARM_ARMED_AWAY, STATE_ALARM_ARMED_HOME, STATE_ALARM_ARMED_NIGHT):
			return

		code = JablotronAlarmControlPanelEntity._clean_code(code)

		if code is None and self._jablotron.is_code_required_for_arm():
			return

		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, state, code)

	def _detect_supported_features(self) -> AlarmControlPanelEntityFeature:
		partially_arming_mode = self._jablotron.partially_arming_mode()

		if partially_arming_mode == PartiallyArmingMode.NOT_SUPPORTED:
			return AlarmControlPanelEntityFeature.ARM_AWAY

		if partially_arming_mode == PartiallyArmingMode.HOME_MODE:
			return AlarmControlPanelEntityFeature.ARM_AWAY | AlarmControlPanelEntityFeature.ARM_HOME

		return AlarmControlPanelEntityFeature.ARM_AWAY | AlarmControlPanelEntityFeature.ARM_NIGHT

	def _detect_code_format(self) -> CodeFormat | None:
		if self._get_state() == STATE_ALARM_DISARMED:
			code_required = self._jablotron.is_code_required_for_arm()
		else:
			code_required = self._jablotron.is_code_required_for_disarm()

		if not code_required:
			return None

		return CodeFormat.TEXT if self._jablotron.code_contains_asterisk() is True else CodeFormat.NUMBER

	@staticmethod
	def _clean_code(code: str | None) -> str | None:
		return None if code == "" else code
