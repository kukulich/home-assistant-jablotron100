from __future__ import annotations

from homeassistant.components.alarm_control_panel import AlarmControlPanelState
from homeassistant.const import STATE_OFF, STATE_ON
import pytest

from custom_components.jablotron100.const import (
	PartiallyArmingMode,
	SectionPrimaryState,
)
from custom_components.jablotron100.jablotron import Jablotron, JablotronSectionState


def section_state(first_byte: int, second_byte: int = 0) -> JablotronSectionState:
	section_binary = "{:08b}{:08b}".format(first_byte, second_byte)
	return Jablotron._parse_jablotron_section_state(section_binary)


@pytest.mark.parametrize(
	(
		"first_byte",
		"expected_primary_state",
		"expected_pending",
		"expected_arming",
		"expected_triggered",
		"expected_problem",
	),
	[
		pytest.param(0x01, SectionPrimaryState.DISARMED, False, False, False, False, id="disarmed"),
		pytest.param(0x02, SectionPrimaryState.ARMED_PARTIALLY, False, False, False, False, id="armed-partially"),
		pytest.param(0x03, SectionPrimaryState.ARMED_FULL, False, False, False, False, id="armed-full"),
		pytest.param(0x05, SectionPrimaryState.SERVICE, False, False, False, False, id="service"),
		pytest.param(0x11, SectionPrimaryState.DISARMED, False, False, True, False, id="triggered-disarmed"),
		pytest.param(0x21, SectionPrimaryState.DISARMED, False, False, False, True, id="problem-disarmed"),
		pytest.param(0x41, SectionPrimaryState.DISARMED, True, False, False, False, id="pending-disarm"),
		pytest.param(0x82, SectionPrimaryState.ARMED_PARTIALLY, False, True, False, False, id="arming-partially"),
		pytest.param(0x83, SectionPrimaryState.ARMED_FULL, False, True, False, False, id="arming-full"),
		pytest.param(0x1B, SectionPrimaryState.ARMED_FULL, False, False, True, False, id="triggered-armed-full"),
		pytest.param(0x07, SectionPrimaryState.OFF, False, False, False, False, id="off"),
		pytest.param(0x9B, SectionPrimaryState.ARMED_FULL, False, True, True, False, id="triggered-while-arming"),
	],
)
def test_parse_section_primary_state(
	first_byte: int,
	expected_primary_state: SectionPrimaryState,
	expected_pending: bool,
	expected_arming: bool,
	expected_triggered: bool,
	expected_problem: bool,
) -> None:
	state = section_state(first_byte)

	assert state.state == expected_primary_state
	assert state.pending is expected_pending
	assert state.arming is expected_arming
	assert state.triggered is expected_triggered
	assert state.problem is expected_problem
	assert not state.sabotage
	assert not state.fire


@pytest.mark.parametrize(
	("second_byte", "expected_triggered", "expected_sabotage", "expected_fire"),
	[
		pytest.param(0x01, False, False, False, id="previous-alarm"),
		pytest.param(0x03, False, False, True, id="fire"),
		pytest.param(0x05, True, False, False, id="instant-alarm"),
		pytest.param(0x09, True, False, False, id="panic-alarm"),
		pytest.param(0x11, False, True, False, id="sabotage"),
		pytest.param(0x41, True, False, False, id="delayed-alarm"),
	],
)
def test_parse_section_alarm_flags(
	second_byte: int,
	expected_triggered: bool,
	expected_sabotage: bool,
	expected_fire: bool,
) -> None:
	state = section_state(0x01, second_byte)

	assert state.triggered is expected_triggered
	assert state.sabotage is expected_sabotage
	assert state.fire is expected_fire


@pytest.mark.parametrize(
	("first_byte", "second_byte", "expected_alarm_state"),
	[
		pytest.param(0x01, 0x00, AlarmControlPanelState.DISARMED, id="disarmed"),
		pytest.param(0x02, 0x00, AlarmControlPanelState.ARMED_NIGHT, id="armed-partially"),
		pytest.param(0x03, 0x00, AlarmControlPanelState.ARMED_AWAY, id="armed-full"),
		pytest.param(0x05, 0x00, None, id="service"),
		pytest.param(0x06, 0x00, None, id="blocked"),
		pytest.param(0x41, 0x00, AlarmControlPanelState.PENDING, id="pending"),
		pytest.param(0x83, 0x00, AlarmControlPanelState.ARMING, id="arming"),
		pytest.param(0x03, 0x04, AlarmControlPanelState.TRIGGERED, id="triggered"),
		pytest.param(0x9B, 0x00, AlarmControlPanelState.TRIGGERED, id="triggered-before-arming"),
	],
)
def test_convert_section_to_alarm_control_panel_state(
	first_byte: int,
	second_byte: int,
	expected_alarm_state: AlarmControlPanelState | None,
) -> None:
	state = section_state(first_byte, second_byte)

	assert (
		Jablotron._convert_jablotron_section_state_to_alarm_state(
			state,
			PartiallyArmingMode.NIGHT_MODE,
		)
		== expected_alarm_state
	)


def test_convert_partially_armed_section_to_home_state() -> None:
	state = section_state(0x02)

	assert (
		Jablotron._convert_jablotron_section_state_to_alarm_state(
			state,
			PartiallyArmingMode.HOME_MODE,
		)
		== AlarmControlPanelState.ARMED_HOME
	)


@pytest.mark.parametrize(
	("second_byte", "expected_problem_state", "expected_fire_state"),
	[
		pytest.param(0x00, STATE_OFF, STATE_OFF, id="no-problem"),
		pytest.param(0x10, STATE_ON, STATE_OFF, id="sabotage"),
		pytest.param(0x02, STATE_OFF, STATE_ON, id="fire"),
	],
)
def test_convert_section_sensor_states(
	second_byte: int,
	expected_problem_state: str,
	expected_fire_state: str,
) -> None:
	state = section_state(0x01, second_byte)

	assert Jablotron._convert_jablotron_section_state_to_problem_sensor_state(state) == expected_problem_state
	assert Jablotron._convert_jablotron_section_state_to_fire_sensor_state(state) == expected_fire_state


def test_convert_sections_packet_stops_at_first_unused_section() -> None:
	packet = bytes.fromhex("51080100030011000700")

	states = Jablotron._convert_sections_states_packet_to_sections_states(packet)

	assert list(states) == [1, 2, 3]
	assert states[1].state == SectionPrimaryState.DISARMED
	assert states[2].state == SectionPrimaryState.ARMED_FULL
	assert states[3].triggered
