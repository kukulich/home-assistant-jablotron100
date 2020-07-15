from concurrent.futures import ThreadPoolExecutor
from homeassistant import core
from homeassistant.const import (
	CONF_PASSWORD,
	EVENT_HOMEASSISTANT_STOP,
	STATE_ALARM_DISARMED,
	STATE_ALARM_ARMED_AWAY,
	STATE_ALARM_ARMED_NIGHT,
	STATE_ALARM_ARMING,
	STATE_ALARM_PENDING,
	STATE_ALARM_TRIGGERED,
)
from homeassistant.helpers.entity import Entity
import re
import threading
import time
from typing import Any, Dict, List, Optional
from .const import (
	CONF_SERIAL_PORT,
	CONF_REQUIRE_CODE_TO_ARM,
	CONF_REQUIRE_CODE_TO_DISARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
	DOMAIN,
	LOGGER,
)
from .errors import (
	ModelNotDetected,
	ModelNotSupported,
	ServiceUnavailable,
	ShouldNotHappen,
)

MAX_WORKERS = 5
TIMEOUT = 30

JABLOTRON_PACKET_INFO = b"\x30\x01\x01\x30\x01\x02\x30\x01\x03\x30\x01\x04\x30\x01\x05\x30\x01\x08\x30\x01\x09\x30\x01\x0A\x30\x01\x0B\x30\x01\x0C\x30\x01\x11\x52\x03\x1A\x01\x00\x3C\x01\x01\x00"
JABLOTRON_PACKET_GET_STATES = b"\x80\x01\x01\x52\x01\x0e"

JABLOTRON_ALARM_STATE_DISARMED = b"\x01"
JABLOTRON_ALARM_STATE_ARMING_FULL = b"\x83"
JABLOTRON_ALARM_STATE_ARMING_PARTIALLY = b"\x82"
JABLOTRON_ALARM_STATE_ARMED_FULL = b"\x03"
JABLOTRON_ALARM_STATE_ARMED_PARTIALLY = b"\x02"
JABLOTRON_ALARM_STATE_PENDING_FULL = b"\x43"
JABLOTRON_ALARM_STATE_PENDING_PARTIALLY = b"\x42"
JABLOTRON_ALARM_STATE_TRIGGERED_FULL = b"\x1b"
JABLOTRON_ALARM_STATE_TRIGGERED_PARTIALLY = b"\x12"
JABLOTRON_ALARM_STATE_OFF = b"\x07"

JABLOTRON_NUMBERS = {
	'0': b'\x30',
	'1': b'\x31',
	'2': b'\x32',
	'3': b'\x33',
	'4': b'\x34',
	'5': b'\x35',
	'6': b'\x36',
	'7': b'\x37',
	'8': b'\x38',
	'9': b'\x39',
}


def decode_bytes(value: bytes) -> str:
	return value.strip(b"\x00").decode().strip("@")


def check_serial_port(serial_port: str) -> None:
	try:
		def reader_loop() -> Optional[str]:
			stream = open(serial_port, "rb")

			model = None

			read_packets = 0
			while read_packets < 2:
				packet = stream.read(64)

				read_packets += 1

				if packet[3:6] == b"\x4a\x41\x2d":
					model = decode_bytes(packet[3:16])
					break

			stream.close()

			return model

		def writer_loop() -> None:
			stream = open(serial_port, "wb")

			stream.write(JABLOTRON_PACKET_INFO)
			time.sleep(0.1)

			stream.close()

		executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
		reader = executor.submit(reader_loop)
		executor.submit(writer_loop)

		model = reader.result(TIMEOUT)

		executor.shutdown()

		if model is None:
			raise ModelNotDetected

		if not re.match(r"JA-101", model):
			raise ModelNotSupported("Model {} not supported".format(model))

	except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError):
		raise ServiceUnavailable


class JablotronCentralUnit:

	def __init__(self, serial_port: str, model: str, hardware_version: str, firmware_version: str):
		self.serial_port: str = serial_port
		self.model: str = model
		self.hardware_version: str = hardware_version
		self.firmware_version: str = firmware_version


class JablotronControl:

	def __init__(self, central_unit: JablotronCentralUnit, name: str, id: str):
		self.central_unit: JablotronCentralUnit = central_unit
		self.name: str = name
		self.id: str = id


class JablotronAlarmControlPanel(JablotronControl):

	def __init__(self, central_unit: JablotronCentralUnit, section: int, name: str, id: str):
		self.section: int = section

		super().__init__(central_unit, name, id)


class Jablotron():

	def __init__(self, hass: core.HomeAssistant, config: Dict[str, str], options: Dict[str, Any]) -> None:
		self._hass: core.HomeAssistant = hass
		self._config: Dict[str, str] = config
		self._options: Dict[str, Any] = options

		self._central_unit: Optional[JablotronCentralUnit] = None
		self._alarm_control_panels: Dict[str, JablotronAlarmControlPanel] = {}

		self._entities: Dict[str, JablotronEntity] = {}

		self._thread_pool_executor: ThreadPoolExecutor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

		self._state_checker_data_updating_event: threading.Event = threading.Event()
		self._state_checker_stop_event: threading.Event = threading.Event()

		self.states: Dict[str, str] = {}
		self.last_update_success: bool = True

	def update_options(self, options: Dict[str, Any]) -> None:
		self._options = options

	def is_code_required_for_state(self, state: str) -> bool:
		if state == STATE_ALARM_DISARMED:
			return self._options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM)

		return self._options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM)

	def initialize(self) -> None:
		try:
			def reader_loop() -> JablotronCentralUnit:
				model = None
				hardware_version = None
				firmware_version = None

				stream = open(self._config[CONF_SERIAL_PORT], "rb")

				read_packets = 0
				while read_packets < 10:
					packet = stream.read(64)

					read_packets += 1

					if packet[3:6] == b"\x4a\x41\x2d":
						model = decode_bytes(packet[3:16])
					elif packet[3:6] == b"\x4c\x4a\x36":
						hardware_version = decode_bytes(packet[3:13])
					elif packet[3:6] == b"\x4c\x4a\x31":
						firmware_version = decode_bytes(packet[3:11])

				stream.close()

				return JablotronCentralUnit(self._config[CONF_SERIAL_PORT], model, hardware_version, firmware_version)

			def writer_loop() -> None:
				self._send_packet(JABLOTRON_PACKET_INFO)

			reader = self._thread_pool_executor.submit(reader_loop)
			self._thread_pool_executor.submit(writer_loop)

			self._central_unit = reader.result(TIMEOUT)

			self._thread_pool_executor.shutdown()

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError):
			raise ServiceUnavailable

		self._thread_pool_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
		self._thread_pool_executor.submit(self._read_state)
		self._thread_pool_executor.submit(self._get_states)

		# Require for the first time
		self._send_packet(JABLOTRON_PACKET_GET_STATES)

		# Magic timeout to get states
		time.sleep(5)

		self._hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, self.shutdown)

	def shutdown(self) -> None:
		self._state_checker_stop_event.set()
		self._thread_pool_executor.shutdown()

	def substribe_entity_for_updates(self, control_id: str, entity) -> None:
		self._entities[control_id] = entity

	def modify_alarm_control_panel_section_state(self, section: int, state: str, code: Optional[str]) -> None:
		if code is None:
			code = self._config[CONF_PASSWORD]

		code_packet = b""
		for code_number in code:
			code_packet += JABLOTRON_NUMBERS[code_number]

		self._send_packet(b"\x80\x08\x03\x39\x39\x39" + code_packet)

		if state == STATE_ALARM_ARMED_AWAY:
			sections = {
				1: b"\xa0",
				2: b"\xa1",
				3: b"\xa2",
				4: b"\xa3",
				5: b"\xa4",
				6: b"\xa5",
				7: b"\xa6",
				8: b"\xa7",
			}

			state_packet = sections[section]

		elif state == STATE_ALARM_ARMED_NIGHT:
			sections = {
				1: b"\xb0",
				2: b"\xb1",
				3: b"\xb2",
				4: b"\xb3",
				5: b"\xb4",
				6: b"\xb5",
				7: b"\xb6",
				8: b"\xb7",
			}

			state_packet = sections[section]

		else:
			sections = {
				1: b"\x90",
				2: b"\x91",
				3: b"\x92",
				4: b"\x93",
				5: b"\x94",
				6: b"\x95",
				7: b"\x96",
				8: b"\x97",
			}

			state_packet = sections[section]

		self._send_packet(b"\x80\x02\x0d" + state_packet)

	def alarm_control_panels(self) -> List[JablotronAlarmControlPanel]:
		if len(self._alarm_control_panels) == 0:
			raise ShouldNotHappen

		alarm_control_panels = []
		for alarm_control_panel in self._alarm_control_panels.values():
			alarm_control_panels.append(alarm_control_panel)

		return alarm_control_panels

	def _read_state(self) -> None:
		while not self._state_checker_stop_event.is_set():
			stream = None

			try:
				stream = open(self._config[CONF_SERIAL_PORT], "rb")

				while True:

					self._state_checker_data_updating_event.clear()

					packet = stream.read(64)

					self._state_checker_data_updating_event.set()

					if not packet:
						self.last_update_success = False
						return

					if packet[:2] == b"\x51\x22":
						self.last_update_success = True

						for number in range(1, 8):
							state_offset = number * 2
							state = packet[state_offset:(state_offset + 1)]

							if state == JABLOTRON_ALARM_STATE_OFF:
								break

							section_id = self._create_section_id(number)

							if section_id not in self._alarm_control_panels:
								self._alarm_control_panels[section_id] = JablotronAlarmControlPanel(
									self._central_unit,
									number,
									self._create_section_name(number),
									section_id,
								)

							hass_state = self._convert_alarm_jablotron_state_to_hass_state(state)

							if section_id in self._entities:
								self._entities[section_id].update_state(hass_state)
							else:
								self.states[section_id] = hass_state

						break

			except Exception as ex:
				LOGGER.error(format(ex))
				self.last_update_success = False

			finally:
				if stream is not None:
					stream.close()

			time.sleep(0.5)

	def _get_states(self):
		while not self._state_checker_stop_event.is_set():
			if not self._state_checker_data_updating_event.wait(0.5):
				self._send_packet(JABLOTRON_PACKET_GET_STATES)
			else:
				time.sleep(30)

	def _send_packet(self, packet) -> None:
		stream = open(self._config[CONF_SERIAL_PORT], "wb")

		stream.write(packet)
		time.sleep(0.1)

		stream.close()

	@staticmethod
	def _create_section_name(section: int) -> str:
		return "Section {}".format(section)

	@staticmethod
	def _create_section_id(section: int) -> str:
		return "section_{}".format(section)

	@staticmethod
	def _convert_alarm_jablotron_state_to_hass_state(state: bytes) -> str:
		if state == JABLOTRON_ALARM_STATE_ARMED_FULL:
			return STATE_ALARM_ARMED_AWAY

		if state == JABLOTRON_ALARM_STATE_ARMED_PARTIALLY:
			return STATE_ALARM_ARMED_NIGHT

		if state == JABLOTRON_ALARM_STATE_ARMING_FULL or state == JABLOTRON_ALARM_STATE_ARMING_PARTIALLY:
			return STATE_ALARM_ARMING

		if state == JABLOTRON_ALARM_STATE_PENDING_FULL or state == JABLOTRON_ALARM_STATE_PENDING_PARTIALLY:
			return STATE_ALARM_PENDING

		if state == JABLOTRON_ALARM_STATE_TRIGGERED_FULL or state == JABLOTRON_ALARM_STATE_TRIGGERED_PARTIALLY:
			return STATE_ALARM_TRIGGERED

		return STATE_ALARM_DISARMED


class JablotronEntity(Entity):
	_state: str

	def __init__(
			self,
			jablotron: Jablotron,
			control: JablotronControl,
	) -> None:
		self._jablotron: Jablotron = jablotron
		self._control: JablotronControl = control

	@property
	def should_poll(self) -> bool:
		return False

	@property
	def available(self) -> bool:
		return self._jablotron.last_update_success

	@property
	def device_info(self) -> Dict[str, str]:
		name = self._control.central_unit.model
		if self._control.central_unit.hardware_version is not None:
			name += " ({})".format(self._control.central_unit.hardware_version)

		return {
			"identifiers": {(DOMAIN, self._control.central_unit.serial_port)},
			"name": name,
			"manufacturer": "Jablotron",
			"sw_version": self._control.central_unit.firmware_version,
		}

	@property
	def name(self) -> str:
		return self._control.name

	@property
	def unique_id(self) -> str:
		return "{}.{}.{}".format(DOMAIN, self._control.central_unit.serial_port, self._control.id)

	@property
	def state(self) -> str:
		return self._jablotron.states[self._control.id]

	async def async_added_to_hass(self) -> None:
		self._jablotron.substribe_entity_for_updates(self._control.id, self)

	def update_state(self, state: str) -> None:
		self._jablotron.states[self._control.id] = state
		self.async_write_ha_state()
