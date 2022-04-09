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

class CentralUnitData(StrEnum):
	BATTERY = "battery"
	BUSES = "buses"
	BATTERY_LEVEL = "battery_level"
	LAN_IP = "lan_ip"

class DeviceData(StrEnum):
	BATTERY = "battery"
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

CODE_MIN_LENGTH: Final = 4
CODE_MAX_LENGTH: Final = 8

STREAM_MAX_WORKERS: Final = 5
STREAM_TIMEOUT: Final = 10
STREAM_PACKET_SIZE: Final = 64

MAX_SECTIONS: Final = 15
MAX_DEVICES: Final = 120
MAX_PG_OUTPUTS: Final = 128

PACKET_GET_SYSTEM_INFO: Final = b"\x30"
PACKET_SYSTEM_INFO: Final = b"\x40"
PACKET_SECTIONS_STATES: Final = b"\x51"
PACKET_DEVICE_STATE: Final = b"\x55"
PACKET_DEVICE_INFO: Final = b"\x90"
PACKET_DEVICES_STATES: Final = b"\xd8"
PACKET_PG_OUTPUTS_STATES: Final = b"\x50"
PACKET_COMMAND: Final = b"\x52"
PACKET_UI_CONTROL: Final = b"\x80"
PACKET_DIAGNOSTICS: Final = b"\x94"
PACKET_DIAGNOSTICS_COMMAND: Final = b"\x96"
PACKET_GET_DEVICES_SECTIONS: Final = b"\x3a"
PACKET_DEVICES_SECTIONS: Final = b"\x3b"

COMMAND_HEARTBEAT: Final = b"\x02"
COMMAND_GET_DEVICE_STATUS: Final = b"\x0a"
COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES: Final = b"\x0e"
COMMAND_ENABLE_DEVICE_STATE_PACKETS: Final = b"\x13"

COMMAND_RESPONSE_DEVICE_STATUS: Final = b"\x8a"

UI_CONTROL_AUTHORISATION_END: Final = b"\x01"
UI_CONTROL_AUTHORISATION_CODE: Final = b"\x03"
UI_CONTROL_MODIFY_SECTION: Final = b"\x0d"
UI_CONTROL_TOGGLE_PG_OUTPUT: Final = b"\x23"

DIAGNOSTICS_ON: Final = b"\x01"
DIAGNOSTICS_OFF: Final = b"\x00"
DIAGNOSTICS_COMMAND_GET_INFO: Final = b"\x09"

DEVICE_PACKET_TYPE_BATTERY: Final = 4
DEVICE_PACKET_TYPE_POWER_SUPPLY_FAULT: Final = 5
DEVICE_PACKET_TYPE_SABOTAGE: Final = 6
DEVICE_PACKET_TYPE_FAULT: Final = 7

EMPTY_PACKET: Final = b"\x00"

# In minutes
TIMEOUT_FOR_DEVICE_STATE_PACKETS: Final = 5

class SystemInfo(Enum):
	MODEL = 2
	HARDWARE_VERSION = 8
	FIRMWARE_VERSION = 9
	REGISTRATION_CODE = 10
	INSTALLATION_NAME = 11

class SectionPrimaryState(Enum):
	DISARMED = 1
	ARMED_PARTIALLY = 2
	ARMED_FULL = 3
	SERVICE = 5
	BLOCKED = 6
	OFF = 7

DEVICE_INFO_SUBPACKET_WIRELESS: Final = b"\x01"
DEVICE_INFO_SUBPACKET_PERIODIC: Final = b"\x9c"
DEVICE_INFO_SUBPACKET_REQUESTED: Final = b"\x0a"
DEVICE_INFO_KNOWN_SUBPACKETS: Final = (
	DEVICE_INFO_SUBPACKET_WIRELESS,
	DEVICE_INFO_SUBPACKET_PERIODIC,
	DEVICE_INFO_SUBPACKET_REQUESTED,
)

class DeviceInfoType(Enum):
	SMOKE = 3
	GSM = 4
	LAN = 6
	POWER = 10
	POWER_PRECISE = 12
	INPUT_VALUE = 14
	INPUT_EXTENDED = 15
	UNKNOWN_1 = 16
	PULSE = 17
	UNKNOWN_2 = 19
	UNKNOWN_GSM = 21

	def is_unknown(self) -> bool:
		return self in (self.UNKNOWN_1, self.UNKNOWN_2, self.UNKNOWN_GSM)

BATTERY_LEVEL_UNKNOWN_STATE: Final = b"\x0b"
BATTERY_LEVEL_EXTERNAL_POWER_SUPPLY: Final = b"\x0c"
BATTERY_LEVEL_MEASURING: Final = b"\x0d"
BATTERY_LEVEL_NO_MEASUREMENT: Final = b"\x0e"
BATTERY_LEVEL_NO_BATTERY: Final = b"\x0f"
BATTERY_LEVELS_TO_IGNORE: Final = (
	BATTERY_LEVEL_UNKNOWN_STATE,
	BATTERY_LEVEL_EXTERNAL_POWER_SUPPLY,
	BATTERY_LEVEL_MEASURING,
	BATTERY_LEVEL_NO_MEASUREMENT,
)

PG_OUTPUT_TURN_ON: Final = b"\x01"
PG_OUTPUT_TURN_OFF: Final = b"\x00"

SIGNAL_STRENGTH_STEP: Final = 5
BATTERY_LEVEL_STEP: Final = 10
