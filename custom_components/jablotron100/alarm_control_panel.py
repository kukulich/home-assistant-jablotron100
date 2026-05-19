from __future__ import annotations
from homeassistant.components.alarm_control_panel import (
	AlarmControlPanelEntity,
	AlarmControlPanelEntityFeature,
	AlarmControlPanelState,
	CodeFormat,
)
from homeassistant.core import callback, HomeAssistant
from homeassistant.helpers.dispatcher import async_dispatcher_connect
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType
from . import JablotronConfigEntry
from .const import EntityType, PartiallyArmingMode
from .jablotron import Jablotron, JablotronEntity, JablotronAlarmControlPanel, JablotronCommonSegment


async def async_setup_entry(hass: HomeAssistant, config_entry: JablotronConfigEntry, async_add_entities: AddEntitiesCallback) -> None:
	jablotron_instance: Jablotron = config_entry.runtime_data

	@callback
	def add_entities() -> None:
		entities = []

		for entity in jablotron_instance.entities[EntityType.ALARM_CONTROL_PANEL].values():
			if entity.id in jablotron_instance.hass_entities:
				continue
			if isinstance(entity, JablotronCommonSegment):
				entities.append(JablotronCommonSegmentEntity(jablotron_instance, entity))
			else:
				entities.append(JablotronAlarmControlPanelEntity(jablotron_instance, entity))

		async_add_entities(entities)

	add_entities()

	config_entry.async_on_unload(
		async_dispatcher_connect(hass, jablotron_instance.signal_entities_added(), add_entities)
	)


class _JablotronAlarmControlPanelEntityBase(JablotronEntity, AlarmControlPanelEntity):
	_code_required_for_disarm: bool = False
	_partially_arming_mode: PartiallyArmingMode

	_attr_name = None

	def _update_attributes(self) -> None:
		super()._update_attributes()

		self._partially_arming_mode = self._jablotron.partially_arming_mode()
		self._code_required_for_disarm = self._jablotron.is_code_required_for_disarm()

		self._attr_code_arm_required = self._jablotron.is_code_required_for_arm()
		self._attr_supported_features = self._detect_supported_features()
		self._attr_alarm_state = self._get_state()
		self._attr_code_format = self._detect_code_format()

	def alarm_disarm(self, code: str | None = None) -> None:
		if self._get_state() == AlarmControlPanelState.DISARMED:
			return

		code = self._resolve_code(code)
		if code is None and self._code_required_for_disarm:
			return

		self._modify_state(AlarmControlPanelState.DISARMED, code)

	def alarm_arm_away(self, code: str | None = None) -> None:
		if self._get_state() == AlarmControlPanelState.ARMED_AWAY:
			return

		code = self._resolve_code(code)
		if code is None and self._attr_code_arm_required:
			return

		self._modify_state(AlarmControlPanelState.ARMED_AWAY, code)

	def alarm_arm_home(self, code: str | None = None) -> None:
		self._arm_partially(AlarmControlPanelState.ARMED_HOME, code)

	def alarm_arm_night(self, code: str | None = None) -> None:
		self._arm_partially(AlarmControlPanelState.ARMED_NIGHT, code)

	def _arm_partially(self, state: AlarmControlPanelState, code: str | None = None) -> None:
		if self._get_state() in (AlarmControlPanelState.ARMED_AWAY, AlarmControlPanelState.ARMED_HOME, AlarmControlPanelState.ARMED_NIGHT):
			return

		code = self._resolve_code(code)
		if code is None and self._attr_code_arm_required:
			return

		self._modify_state(state, code)

	def _resolve_code(self, code: str | None) -> str | None:
		cleaned = None if code == "" else code
		return self.code_or_default_code(cleaned)

	def _modify_state(self, state: AlarmControlPanelState, code: str | None) -> None:
		raise NotImplementedError

	def _detect_supported_features(self) -> AlarmControlPanelEntityFeature:
		if self._partially_arming_mode == PartiallyArmingMode.NOT_SUPPORTED:
			return AlarmControlPanelEntityFeature.ARM_AWAY

		if self._partially_arming_mode == PartiallyArmingMode.HOME_MODE:
			return AlarmControlPanelEntityFeature.ARM_AWAY | AlarmControlPanelEntityFeature.ARM_HOME

		return AlarmControlPanelEntityFeature.ARM_AWAY | AlarmControlPanelEntityFeature.ARM_NIGHT

	def _detect_code_format(self) -> CodeFormat | None:
		if self._get_state() == AlarmControlPanelState.DISARMED:
			code_required = self._attr_code_arm_required
		else:
			code_required = self._code_required_for_disarm

		if not code_required:
			return None

		return CodeFormat.TEXT if self._jablotron.code_contains_asterisk() is True else CodeFormat.NUMBER


class JablotronAlarmControlPanelEntity(_JablotronAlarmControlPanelEntityBase):
	_control: JablotronAlarmControlPanel
	_changed_by: str | None = None

	def _update_attributes(self) -> None:
		super()._update_attributes()
		self._attr_changed_by = self._changed_by

	def update_state(self, state: StateType) -> None:
		if self._get_state() != state:
			self._changed_by = self._jablotron.last_authorized_user_or_device()

		super().update_state(state)

	def _modify_state(self, state: AlarmControlPanelState, code: str | None) -> None:
		self._jablotron.modify_alarm_control_panel_section_state(self._control.section, state, code)


class JablotronCommonSegmentEntity(_JablotronAlarmControlPanelEntityBase):
	_control: JablotronCommonSegment

	def _update_attributes(self) -> None:
		super()._update_attributes()
		self._attr_extra_state_attributes = {
			"sections": list(self._control.sections),
		}

	def _modify_state(self, state: AlarmControlPanelState, code: str | None) -> None:
		self._jablotron.modify_common_segment_state(self._control, state, code)
