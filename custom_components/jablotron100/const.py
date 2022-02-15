"""Jablotron specific constants."""
import logging
from enum import Enum
from homeassistant.backports.enum import StrEnum
from typing import Final

LOGGER: Final = logging.getLogger(__package__)

DOMAIN: Final = "jablotron100"
NAME: Final = "Jablotron"

EVENT_WRONG_CODE: Final = "{}_wrong_code".format(DOMAIN)

CONF_SERIAL_PORT: Final = "serial_port"
CONF_NUMBER_OF_DEVICES: Final = "number_of_devices"
CONF_NUMBER_OF_PG_OUTPUTS: Final = "number_of_pg_outputs"
CONF_DEVICES: Final = "devices"
CONF_REQUIRE_CODE_TO_ARM: Final = "require_code_to_arm"
CONF_REQUIRE_CODE_TO_DISARM: Final = "require_code_to_disarm"
CONF_ENABLE_DEBUGGING: Final = "enable_debugging"

CONF_LOG_ALL_INCOMING_PACKETS: Final = "log_all_incoming_packets"
CONF_LOG_ALL_OUTCOMING_PACKETS: Final = "log_all_outcoming_packets"
CONF_LOG_SECTIONS_PACKETS: Final = "log_sections_packets"
CONF_LOG_PG_OUTPUTS_PACKETS: Final = "log_pg_outputs_packets"
CONF_LOG_DEVICES_PACKETS: Final = "log_devices_packets"

DEFAULT_SERIAL_PORT: Final = "/dev/hidraw0"

DATA_JABLOTRON: Final = "jablotron"
DATA_OPTIONS_UPDATE_UNSUBSCRIBER: Final = "options_update_unsubscriber"

DEFAULT_CONF_REQUIRE_CODE_TO_ARM: Final = False
DEFAULT_CONF_REQUIRE_CODE_TO_DISARM: Final = True
DEFAULT_CONF_ENABLE_DEBUGGING: Final = False

class DeviceData(StrEnum):
	BATTERY_LEVEL = "battery_level"
	CONNECTION = "connection"
	SECTION = "section"
	SIGNAL_STRENGTH = "signal_strength"

class DeviceConnection(StrEnum):
	WIRED = "wired"
	WIRELESS = "wireless"

class DeviceNumber(Enum):
	CENTRAL_UNIT = 0
	MOBILE_APPLICATION = 250
	USB = 254

class DeviceType(StrEnum):
	CENTRAL_UNIT = "central_unit"
	KEYPAD = "keypad"
	SIREN_OUTDOOR = "outdoor_siren"
	SIREN_INDOOR = "indoor_siren"
	MOTION_DETECTOR = "motion_detector"
	WINDOW_OPENING_DETECTOR = "window_opening_detector"
	DOOR_OPENING_DETECTOR = "door_opening_detector"
	GARAGE_DOOR_OPENING_DETECTOR = "garage_door_opening_detector"
	GLASS_BREAK_DETECTOR = "glass_break_detector"
	SMOKE_DETECTOR = "smoke_detector"
	FLOOD_DETECTOR = "flood_detector"
	GAS_DETECTOR = "gas_detector"
	THERMOSTAT = "thermostat"
	THERMOMETER = "thermometer"
	LOCK = "lock"
	TAMPER = "tamper"
	BUTTON = "button"
	KEY_FOB = "key_fob"
	ELECTRICITY_METER_WITH_PULSE_OUTPUT = "electricity_meter_with_pulse_output"
	RADIO_MODULE = "radio_module"
	CUSTOM = "custom"
	OTHER = "other"
	EMPTY = "empty"

	def get_name(self) -> str:
		name = self._value_.replace("_", " ")
		return name[0:1].upper() + name[1:]

class EntityType(StrEnum):
	ALARM_CONTROL_PANEL = "alarm_control_panel"
	BATTERY_LEVEL = "battery_level"
	CURRENT = "current"
	DEVICE_STATE = "device_state"
	FIRE = "fire"
	GSM_SIGNAL = "gsm_signal"
	IP = "ip"
	LAN_CONNECTION = "lan_connection"
	PULSE = "pulse"
	PROBLEM = "problem"
	PROGRAMMABLE_OUTPUT = "programmable_output"
	SIGNAL_STRENGTH = "signal_strength"
	TEMPERATURE = "temperature"
	VOLTAGE = "voltage"

MAX_SECTIONS: Final = 15
MAX_DEVICES: Final = 120
MAX_PG_OUTPUTS: Final = 128

CODE_MIN_LENGTH: Final = 4
CODE_MAX_LENGTH: Final = 8
