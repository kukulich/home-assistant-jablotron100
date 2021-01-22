"""Jablotron specific constants."""
import logging

LOGGER = logging.getLogger(__package__)

DOMAIN = "jablotron100"
NAME = "Jablotron"

CONF_SERIAL_PORT = "serial_port"
CONF_NUMBER_OF_DEVICES = "number_of_devices"
CONF_NUMBER_OF_PG_OUTPUTS = "number_of_pg_outputs"
CONF_DEVICES = "devices"
CONF_REQUIRE_CODE_TO_ARM = "require_code_to_arm"
CONF_REQUIRE_CODE_TO_DISARM = "require_code_to_disarm"
CONF_ENABLE_DEBUGGING = "enable_debugging"

CONF_LOG_ALL_INCOMING_PACKETS = "log_all_incoming_packets"
CONF_LOG_ALL_OUTCOMING_PACKETS = "log_all_outcoming_packets"
CONF_LOG_SECTIONS_PACKETS = "log_sections_packets"
CONF_LOG_PG_OUTPUTS_PACKETS = "log_pg_outputs_packets"
CONF_LOG_DEVICES_PACKETS = "log_devices_packets"

DEFAULT_SERIAL_PORT = "/dev/hidraw0"

DATA_JABLOTRON = "jablotron"
DATA_OPTIONS_UPDATE_UNSUBSCRIBER = "options_update_unsubscriber"

DEFAULT_CONF_REQUIRE_CODE_TO_ARM = False
DEFAULT_CONF_REQUIRE_CODE_TO_DISARM = True
DEFAULT_CONF_ENABLE_DEBUGGING = False

DEVICE_DATA_CONNECTION = "connection"
DEVICE_DATA_BATTERY_LEVEL = "battery_level"
DEVICE_DATA_SIGNAL_STRENGTH = "signal_strength"

DEVICE_CONNECTION_WIRED = "wired"
DEVICE_CONNECTION_WIRELESS = "wireless"

DEVICE_EMPTY = "empty"
DEVICE_BUTTON = "button"
DEVICE_KEY_FOB = "key_fob"
DEVICE_KEYPAD = "keypad"
DEVICE_SIREN_OUTDOOR = "outdoor_siren"
DEVICE_SIREN_INDOOR = "indoor_siren"
DEVICE_MOTION_DETECTOR = "motion_detector"
DEVICE_WINDOW_OPENING_DETECTOR = "window_opening_detector"
DEVICE_DOOR_OPENING_DETECTOR = "door_opening_detector"
DEVICE_GARAGE_DOOR_OPENING_DETECTOR = "garage_door_opening_detector"
DEVICE_GLASS_BREAK_DETECTOR = "glass_break_detector"
DEVICE_SMOKE_DETECTOR = "smoke_detector"
DEVICE_FLOOD_DETECTOR = "flood_detector"
DEVICE_GAS_DETECTOR = "gas_detector"
DEVICE_THERMOSTAT = "thermostat"
DEVICE_LOCK = "lock"
DEVICE_CUSTOM = "custom"
DEVICE_OTHER = "other"

DEVICES = {
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
	DEVICE_LOCK: "Lock",
	DEVICE_CUSTOM: "Custom binary sensor",
	DEVICE_OTHER: "Other",
	DEVICE_EMPTY: "Empty",
}

MAX_SECTIONS = 15
MAX_DEVICES = 120
MAX_PG_OUTPUTS = 128

CODE_MIN_LENGTH = 4
CODE_MAX_LENGTH = 8
