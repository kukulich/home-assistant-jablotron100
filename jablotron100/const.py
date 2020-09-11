"""Jablotron specific constants."""
import logging

LOGGER = logging.getLogger(__package__)

DOMAIN = "jablotron100"
NAME = "Jablotron"

CONF_SERIAL_PORT = "serial_port"
CONF_NUMBER_OF_DEVICES = "number_of_devices"
CONF_DEVICES = "devices"
CONF_REQUIRE_CODE_TO_ARM = "require_code_to_arm"
CONF_REQUIRE_CODE_TO_DISARM = "require_code_to_disarm"

DEFAULT_SERIAL_PORT = "/dev/hidraw0"

DATA_JABLOTRON = "jablotron"
DATA_OPTIONS_UPDATE_UNSUBSCRIBER = "options_update_unsubscriber"

DEFAULT_CONF_REQUIRE_CODE_TO_ARM = False
DEFAULT_CONF_REQUIRE_CODE_TO_DISARM = True

DEVICE_KEYPAD = "keypad"
DEVICE_SIREN = "siren"
DEVICE_MOTION_DETECTOR = "motion_detector"
DEVICE_WINDOW_OPENING_DETECTOR = "window_opening_detector"
DEVICE_DOOR_OPENING_DETECTOR = "door_opening_detector"
DEVICE_GLASS_BREAK_DETECTOR = "glass_break_detector"
DEVICE_SMOKE_DETECTOR = "smoke_detector"
DEVICE_FLOOD_DETECTOR = "flood_detector"
DEVICE_GAS_DETECTOR = "gas_detector"
DEVICE_OTHER = "other"

DEVICES = {
	DEVICE_KEYPAD: "Keypad",
	DEVICE_SIREN: "Siren",
	DEVICE_MOTION_DETECTOR: "Motion detector",
	DEVICE_WINDOW_OPENING_DETECTOR: "Window opening detector",
	DEVICE_DOOR_OPENING_DETECTOR: "Door opening detector",
	DEVICE_GLASS_BREAK_DETECTOR: "Glass break detector",
	DEVICE_SMOKE_DETECTOR: "Smoke detector",
	DEVICE_FLOOD_DETECTOR: "Flood detector",
	DEVICE_GAS_DETECTOR: "Gas detector",
	DEVICE_OTHER: "Other",
}

MAX_SECTIONS = 16
MAX_DEVICES = 36

