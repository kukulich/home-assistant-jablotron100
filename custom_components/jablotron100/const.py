"""Jablotron specific constants."""
import logging
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

DEVICE_DATA_CONNECTION: Final = "connection"
DEVICE_DATA_BATTERY_LEVEL: Final = "battery_level"
DEVICE_DATA_SIGNAL_STRENGTH: Final = "signal_strength"

DEVICE_CONNECTION_WIRED: Final = "wired"
DEVICE_CONNECTION_WIRELESS: Final = "wireless"

DEVICE_CENTRAL_UNIT_NUMBER: Final = 0
DEVICE_MOBILE_APPLICATION_NUMBER: Final = 250
DEVICE_USB_NUMBER: Final = 254

DEVICE_CENTRAL_UNIT: Final = "central_unit"
DEVICE_EMPTY: Final = "empty"
DEVICE_BUTTON: Final = "button"
DEVICE_KEY_FOB: Final = "key_fob"
DEVICE_KEYPAD: Final = "keypad"
DEVICE_SIREN_OUTDOOR: Final = "outdoor_siren"
DEVICE_SIREN_INDOOR: Final = "indoor_siren"
DEVICE_MOTION_DETECTOR: Final = "motion_detector"
DEVICE_WINDOW_OPENING_DETECTOR: Final = "window_opening_detector"
DEVICE_DOOR_OPENING_DETECTOR: Final = "door_opening_detector"
DEVICE_GARAGE_DOOR_OPENING_DETECTOR: Final = "garage_door_opening_detector"
DEVICE_GLASS_BREAK_DETECTOR: Final = "glass_break_detector"
DEVICE_SMOKE_DETECTOR: Final = "smoke_detector"
DEVICE_FLOOD_DETECTOR: Final = "flood_detector"
DEVICE_GAS_DETECTOR: Final = "gas_detector"
DEVICE_THERMOSTAT: Final = "thermostat"
DEVICE_THERMOMETER: Final = "thermometer"
DEVICE_LOCK: Final = "lock"
DEVICE_TAMPER: Final = "tamper"
DEVICE_ELECTRICITY_METER_WITH_PULSE_OUTPUT: Final = "electricity_meter_with_pulse_output"
DEVICE_CUSTOM: Final = "custom"
DEVICE_OTHER: Final = "other"

DEVICES: Final = {
	DEVICE_CENTRAL_UNIT: "Central unit",
	DEVICE_KEYPAD: "Keypad",
	DEVICE_SIREN_OUTDOOR: "Outdoor siren",
	DEVICE_SIREN_INDOOR: "Indoor siren",
	DEVICE_MOTION_DETECTOR: "Motion detector",
	DEVICE_WINDOW_OPENING_DETECTOR: "Window opening detector",
	DEVICE_DOOR_OPENING_DETECTOR: "Door opening detector",
	DEVICE_GARAGE_DOOR_OPENING_DETECTOR: "Garage door opening detector",
	DEVICE_GLASS_BREAK_DETECTOR: "Glass break detector",
	DEVICE_SMOKE_DETECTOR: "Smoke detector",
	DEVICE_FLOOD_DETECTOR: "Flood detector",
	DEVICE_GAS_DETECTOR: "Gas detector",
	DEVICE_KEY_FOB: "Key fob",
	DEVICE_BUTTON: "Button",
	DEVICE_THERMOSTAT: "Thermostat",
	DEVICE_THERMOMETER: "Thermometer",
	DEVICE_LOCK: "Lock",
	DEVICE_CUSTOM: "Custom binary sensor",
	DEVICE_TAMPER: "Tamper",
	DEVICE_ELECTRICITY_METER_WITH_PULSE_OUTPUT: "Electricity meter with pulse output",
	DEVICE_OTHER: "Other",
	DEVICE_EMPTY: "Empty",
}

MAX_SECTIONS: Final = 15
MAX_DEVICES: Final = 120
MAX_PG_OUTPUTS: Final = 128

CODE_MIN_LENGTH: Final = 4
CODE_MAX_LENGTH: Final = 8
