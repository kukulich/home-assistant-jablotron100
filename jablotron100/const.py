"""Jablotron specific constants."""
import logging

LOGGER = logging.getLogger(__package__)

DOMAIN = "jablotron100"
NAME = "Jablotron"

CONF_SERIAL_PORT = "serial_port"
CONF_REQUIRE_CODE_TO_ARM = "require_code_to_arm"
CONF_REQUIRE_CODE_TO_DISARM = "require_code_to_disarm"

DEFAULT_SERIAL_PORT = "/dev/hidraw0"

DATA_JABLOTRON = "jablotron"
DATA_OPTIONS_UPDATE_UNSUBSCRIBER = "options_update_unsubscriber"

DEFAULT_CONF_REQUIRE_CODE_TO_ARM = False
DEFAULT_CONF_REQUIRE_CODE_TO_DISARM = True
