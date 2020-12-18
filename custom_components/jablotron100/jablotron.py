import binascii
from concurrent.futures import ThreadPoolExecutor
import copy
import datetime
from homeassistant import core
from homeassistant.const import (
	ATTR_BATTERY_LEVEL,
	CONF_PASSWORD,
	EVENT_HOMEASSISTANT_STOP,
	STATE_ALARM_DISARMED,
	STATE_ALARM_ARMED_AWAY,
	STATE_ALARM_ARMED_NIGHT,
	STATE_ALARM_ARMING,
	STATE_ALARM_PENDING,
	STATE_ALARM_TRIGGERED,
	STATE_OFF,
	STATE_ON,
)
from homeassistant.helpers import storage
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.typing import StateType
import math
import re
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Union
from .const import (
	CONF_DEVICES,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_SERIAL_PORT,
	CONF_REQUIRE_CODE_TO_ARM,
	CONF_REQUIRE_CODE_TO_DISARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
	DEVICE_CONNECTION_WIRED,
	DEVICE_CONNECTION_WIRELESS,
	DEVICE_DATA_CONNECTION,
	DEVICE_DATA_BATTERY_LEVEL,
	DEVICE_DATA_SIGNAL_STRENGTH,
	DEVICES,
	DEVICE_EMPTY,
	DEVICE_KEYPAD,
	DEVICE_SIREN_OUTDOOR,
	DEVICE_OTHER,
	DOMAIN,
	LOGGER,
	MAX_SECTIONS,
)
from .errors import (
	ModelNotDetected,
	ModelNotSupported,
	ServiceUnavailable,
	ShouldNotHappen,
)

MAX_WORKERS = 5
TIMEOUT = 10
PACKET_READ_SIZE = 64

STORAGE_VERSION = 1
STORAGE_STATES_KEY = "states"
STORAGE_DEVICES_KEY = "devices"

JABLOTRON_PACKET_GET_SYSTEM_INFO = b"\x30"
JABLOTRON_PACKET_SYSTEM_INFO = b"\x40"
JABLOTRON_PACKET_SECTIONS_STATES = b"\x51"
JABLOTRON_PACKET_DEVICE_STATE = b"\x55"
JABLOTRON_PACKET_DEVICES_STATES = b"\xd8"
JABLOTRON_PACKET_PG_OUTPUTS_STATES = b"\x50"
JABLOTRON_PACKET_COMMAND = b"\x52"
JABLOTRON_PACKET_UI_CONTROL = b"\x80"

JABLOTRON_COMMAND_HEARTBEAT = b"\x02"
JABLOTRON_COMMAND_GET_DEVICE_INFO = b"\x0a"
JABLOTRON_COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES = b"\x0e"
JABLOTRON_COMMAND_ENABLE_DEVICE_STATE_PACKETS = b"\x13"

JABLOTRON_COMMAND_RESPONSE_DEVICE_INFO = b"\x8a"

JABLOTRON_UI_CONTROL_AUTHORISATION_END = b"\x01"
JABLOTRON_UI_CONTROL_AUTHORISATION_CODE = b"\x03"
JABLOTRON_UI_CONTROL_MODIFY_SECTION = b"\x0d"
JABLOTRON_UI_CONTROL_TOGGLE_PG_OUTPUT = b"\x23"

JABLOTRON_PACKETS_DEVICE_ACTIVITY = [
	b"\x00", b"\x01", b"\x02", b"\x03", b"\x0a",
	b"\x0c", b"\x0d", b"\x0e", b"\x22", b"\x24",
	b"\x2d", b"\x33", b"\x3e", b"\x4f", b"\x80",
	b"\x81", b"\xa2", b"\xa3", b"\xa4", b"\xa6",
	b"\xa8", b"\xbe",
]

# In minutes
JABLOTRON_TIMEOUT_FOR_DEVICE_STATE_PACKETS = 5

JABLOTRON_SYSTEM_INFO_MODEL = 2
JABLOTRON_SYSTEM_INFO_HARDWARE_VERSION = 8
JABLOTRON_SYSTEM_INFO_FIRMWARE_VERSION = 9
JABLOTRON_SYSTEM_INFO_REGISTRATION_CODE = 10
JABLOTRON_SYSTEM_INFO_INSTALLATION_NAME = 11

JABLOTRON_SECTION_PRIMARY_STATE_DISARMED = 1
JABLOTRON_SECTION_PRIMARY_STATE_ARMED_PARTIALLY = 2
JABLOTRON_SECTION_PRIMARY_STATE_ARMED_FULL = 3
JABLOTRON_SECTION_PRIMARY_STATE_SERVICE = 5
JABLOTRON_SECTION_PRIMARY_STATE_TRIGGERED = 11
JABLOTRON_SECTION_PRIMARY_STATES = [
	JABLOTRON_SECTION_PRIMARY_STATE_DISARMED,
	JABLOTRON_SECTION_PRIMARY_STATE_ARMED_PARTIALLY,
	JABLOTRON_SECTION_PRIMARY_STATE_ARMED_FULL,
	JABLOTRON_SECTION_PRIMARY_STATE_SERVICE,
	JABLOTRON_SECTION_PRIMARY_STATE_TRIGGERED,
]

JABLOTRON_SECTION_SECONDARY_STATE_NOTHING = 0
JABLOTRON_SECTION_SECONDARY_STATE_TRIGGERED = 1
JABLOTRON_SECTION_SECONDARY_STATE_PROBLEM = 2
JABLOTRON_SECTION_SECONDARY_STATE_PENDING = 4
JABLOTRON_SECTION_SECONDARY_STATE_ARMING = 8
JABLOTRON_SECTION_SECONDARY_STATES = [
	JABLOTRON_SECTION_SECONDARY_STATE_NOTHING,
	JABLOTRON_SECTION_SECONDARY_STATE_TRIGGERED,
	JABLOTRON_SECTION_SECONDARY_STATE_PROBLEM,
	JABLOTRON_SECTION_SECONDARY_STATE_PENDING,
	JABLOTRON_SECTION_SECONDARY_STATE_ARMING,
]

JABLOTRON_SECTION_TERTIARY_STATE_OFF = 0
JABLOTRON_SECTION_TERTIARY_STATE_ON = 1
JABLOTRON_SECTION_TERTIARY_STATES = [
	JABLOTRON_SECTION_TERTIARY_STATE_OFF,
	JABLOTRON_SECTION_TERTIARY_STATE_ON,
]

JABLOTRON_SIGNAL_STRENGTH_STEP = 5
JABLOTRON_BATTERY_LEVEL_STEP = 10

JABLOTRON_PG_OUTPUT_TURN_ON = 1
JABLOTRON_PG_OUTPUT_TURN_OFF = 2


def check_serial_port(serial_port: str) -> None:
	stop_event = threading.Event()
	thread_pool_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

	def reader_thread() -> Optional[str]:
		detected_model = None

		stream = open(serial_port, "rb")

		try:
			while not stop_event.is_set():
				raw_packet = stream.read(PACKET_READ_SIZE)
				LOGGER.debug("Check serial port: {}".format(Jablotron.format_packet_to_string(raw_packet)))

				packets = Jablotron.get_packets_from_packet(raw_packet)
				for packet in packets:
					if (
						packet[:1] == JABLOTRON_PACKET_SYSTEM_INFO
						and Jablotron.bytes_to_int(packet[2:3]) == JABLOTRON_SYSTEM_INFO_MODEL
					):
						try:
							detected_model = Jablotron.decode_system_info_packet(packet)
							break
						except UnicodeDecodeError:
							# Will try again
							pass

				if detected_model is not None:
					break

		finally:
			stream.close()

		return detected_model

	def writer_thread() -> None:
		while not stop_event.is_set():
			stream = open(serial_port, "wb")

			stream.write(Jablotron.create_packet_get_system_info(JABLOTRON_SYSTEM_INFO_MODEL))
			time.sleep(0.1)

			stream.close()

			time.sleep(1)

	try:
		reader = thread_pool_executor.submit(reader_thread)
		thread_pool_executor.submit(writer_thread)

		model = reader.result(TIMEOUT)

		if model is None:
			raise ModelNotDetected

		if not re.match(r"^JA-10[1367]", model):
			LOGGER.debug("Unsupported model: {}", model)
			raise ModelNotSupported("Model {} not supported".format(model))

	except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError):
		raise ServiceUnavailable

	finally:
		stop_event.set()
		thread_pool_executor.shutdown()


class JablotronCentralUnit:

	def __init__(self, serial_port: str, model: str, hardware_version: str, firmware_version: str):
		self.serial_port: str = serial_port
		self.model: str = model
		self.hardware_version: str = hardware_version
		self.firmware_version: str = firmware_version


class JablotronHassDevice:

	def __init__(self, id: str, name: str, battery_level: Optional[int] = None):
		self.id: str = id
		self.name: str = name
		self.battery_level: Optional[int] = battery_level


class JablotronControl:

	def __init__(self, central_unit: JablotronCentralUnit, hass_device: Optional[JablotronHassDevice], id: str, name: str):
		self.central_unit: JablotronCentralUnit = central_unit
		self.hass_device: Optional[JablotronHassDevice] = hass_device
		self.id: str = id
		self.name: str = name


class JablotronDevice(JablotronControl):

	def __init__(self, central_unit: JablotronCentralUnit, hass_device: JablotronHassDevice, id: str, name: str, type: str):
		self.type: str = type

		super().__init__(central_unit, hass_device, id, name)


class JablotronAlarmControlPanel(JablotronControl):

	def __init__(self, central_unit: JablotronCentralUnit, hass_device: JablotronHassDevice, id: str, name: str, section: int):
		self.section: int = section

		super().__init__(central_unit, hass_device, id, name)


class JablotronProgrammableOutput(JablotronControl):

	def __init__(self, central_unit: JablotronCentralUnit, id: str, name: str, pg_output_number: int):
		self.pg_output_number: int = pg_output_number

		super().__init__(central_unit, None, id, name)


class Jablotron:

	def __init__(self, hass: core.HomeAssistant, config: Dict[str, Any], options: Dict[str, Any]) -> None:
		self._hass: core.HomeAssistant = hass
		self._config: Dict[str, Any] = config
		self._options: Dict[str, Any] = options

		self._central_unit: Optional[JablotronCentralUnit] = None
		self._device_hass_devices: Dict[str, JablotronHassDevice] = {}

		self._alarm_control_panels: List[JablotronAlarmControlPanel] = []
		self._section_problem_sensors: List[JablotronControl] = []
		self._device_sensors: List[JablotronDevice] = []
		self._device_problem_sensors: List[JablotronControl] = []
		self._device_signal_strength_sensors: List[JablotronControl] = []
		self._device_battery_level_sensors: List[JablotronControl] = []
		self._lan_connection: Optional[JablotronControl] = None
		self._gsm_signal_sensor: Optional[JablotronControl] = None
		self._gsm_signal_strength_sensor: Optional[JablotronControl] = None
		self._pg_outputs: List[JablotronProgrammableOutput] = []

		self._entities: Dict[str, JablotronEntity] = {}

		self._state_checker_thread_pool_executor: Optional[ThreadPoolExecutor] = None
		self._state_checker_stop_event: threading.Event = threading.Event()
		self._state_checker_data_updating_event: threading.Event = threading.Event()

		self._store: storage.Store = storage.Store(hass, STORAGE_VERSION, DOMAIN)
		self._stored_data: Optional[dict] = None

		self._devices_data: Dict[str, Dict[str, Union[str, int, None]]] = {}

		self.states: Dict[str, StateType] = {}
		self.last_update_success: bool = False
		self.in_service_mode = False

	def update_options(self, options: Dict[str, Any]) -> None:
		self._options = options
		self._update_all_entities()

	def is_code_required_for_disarm(self) -> bool:
		return self._options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM)

	def is_code_required_for_arm(self) -> bool:
		return self._options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM)

	async def initialize(self) -> None:
		def shutdown_event(_):
			self.shutdown()

		self._hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, shutdown_event)

		await self._load_stored_data()

		self._detect_central_unit()
		self._detect_sections_and_pg_outputs()
		self._detect_devices()
		self._create_devices()
		self._create_lan_connection()
		self._create_gsm_sensors()

		# Initialize states checker
		self._state_checker_thread_pool_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)
		self._state_checker_thread_pool_executor.submit(self._read_packets)
		self._state_checker_thread_pool_executor.submit(self._keepalive)

		self.last_update_success = True

	def central_unit(self) -> JablotronCentralUnit:
		return self._central_unit

	def shutdown(self) -> None:
		self._state_checker_stop_event.set()

		# Send packet so read thread can finish
		self._send_packet(
			Jablotron.create_packet_command(JABLOTRON_COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES)
			+ Jablotron.create_packet_ui_control(JABLOTRON_UI_CONTROL_AUTHORISATION_END)
		)

		if self._state_checker_thread_pool_executor is not None:
			self._state_checker_thread_pool_executor.shutdown()

	def substribe_entity_for_updates(self, control_id: str, entity) -> None:
		self._entities[control_id] = entity

	def modify_alarm_control_panel_section_state(self, section: int, state: str, code: Optional[str]) -> None:
		if code is None:
			code = self._config[CONF_PASSWORD]

		int_packets = {
			STATE_ALARM_DISARMED: 143,
			STATE_ALARM_ARMED_AWAY: 159,
			STATE_ALARM_ARMED_NIGHT: 175,
		}

		state_packet = Jablotron.int_to_bytes(int_packets[state] + section)

		packet = b""

		if code != self._config[CONF_PASSWORD]:
			packet += Jablotron.create_packet_ui_control(JABLOTRON_UI_CONTROL_AUTHORISATION_END)
			packet += Jablotron.create_packet_authorisation_code(code)

		packet += Jablotron.create_packet_ui_control(JABLOTRON_UI_CONTROL_MODIFY_SECTION, state_packet)

		self._send_packet(packet)

		if code != self._config[CONF_PASSWORD]:
			self._send_packet(Jablotron.create_packet_keapalive(self._config[CONF_PASSWORD]))

		# Update states - should fix state when invalid code was inserted
		self._send_packet(Jablotron.create_packet_command(JABLOTRON_COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))

	def toggle_pg_output(self, pg_output_number: int, state: str) -> None:
		pg_output_number_packet = Jablotron.int_to_bytes(pg_output_number - 1)
		state_packet = Jablotron.int_to_bytes(JABLOTRON_PG_OUTPUT_TURN_ON if state == STATE_ON else JABLOTRON_PG_OUTPUT_TURN_OFF)

		packet = Jablotron.create_packet_ui_control(JABLOTRON_UI_CONTROL_TOGGLE_PG_OUTPUT, pg_output_number_packet + state_packet)

		self._send_packet(packet)

	def alarm_control_panels(self) -> List[JablotronAlarmControlPanel]:
		return self._alarm_control_panels

	def section_problem_sensors(self) -> List[JablotronControl]:
		return self._section_problem_sensors

	def device_sensors(self) -> List[JablotronDevice]:
		return self._device_sensors

	def device_problem_sensors(self) -> List[JablotronControl]:
		return self._device_problem_sensors

	def device_signal_strength_sensors(self) -> List[JablotronControl]:
		return self._device_signal_strength_sensors

	def device_battery_level_sensors(self) -> List[JablotronControl]:
		return self._device_battery_level_sensors

	def lan_connection(self) -> Optional[JablotronControl]:
		return self._lan_connection

	def gsm_signal_sensor(self) -> Optional[JablotronControl]:
		return self._gsm_signal_sensor

	def gsm_signal_strength_sensor(self) -> Optional[JablotronControl]:
		return self._gsm_signal_strength_sensor

	def pg_outputs(self) -> List[JablotronProgrammableOutput]:
		return self._pg_outputs

	def _update_all_entities(self) -> None:
		for entity in self._entities.values():
			entity.async_write_ha_state()

	async def _load_stored_data(self) -> None:
		self._stored_data = await self._store.async_load()

		if self._stored_data is None:
			self._stored_data = {}

		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			return

		if STORAGE_STATES_KEY in self._stored_data[serial_port]:
			self.states = copy.deepcopy(self._stored_data[serial_port][STORAGE_STATES_KEY])

		if STORAGE_DEVICES_KEY in self._stored_data[serial_port]:
			self._devices_data = copy.deepcopy(self._stored_data[serial_port][STORAGE_DEVICES_KEY])

	def _detect_central_unit(self) -> None:
		stop_event = threading.Event()
		thread_pool_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

		def reader_thread() -> Optional[JablotronCentralUnit]:
			model = None
			hardware_version = None
			firmware_version = None

			stream = open(self._config[CONF_SERIAL_PORT], "rb")

			try:
				while not stop_event.is_set():
					raw_packet = stream.read(PACKET_READ_SIZE)
					packets = Jablotron.get_packets_from_packet(raw_packet)

					for packet in packets:
						if packet[:1] != JABLOTRON_PACKET_SYSTEM_INFO:
							continue

						LOGGER.debug("Info packet: {}".format(Jablotron.format_packet_to_string(packet)))

						try:
							info_type = Jablotron.bytes_to_int(packet[2:3])
							if info_type == JABLOTRON_SYSTEM_INFO_MODEL:
								model = Jablotron.decode_system_info_packet(packet)
							elif info_type == JABLOTRON_SYSTEM_INFO_HARDWARE_VERSION:
								hardware_version = Jablotron.decode_system_info_packet(packet)
							elif info_type == JABLOTRON_SYSTEM_INFO_FIRMWARE_VERSION:
								firmware_version = Jablotron.decode_system_info_packet(packet)
						except UnicodeDecodeError:
							# Try again
							pass

					if model is not None and hardware_version is not None and firmware_version is not None:
						break
			finally:
				stream.close()

			if model is None or hardware_version is None or firmware_version is None:
				return None

			return JablotronCentralUnit(self._config[CONF_SERIAL_PORT], model, hardware_version, firmware_version)

		def writer_thread() -> None:
			while not stop_event.is_set():
				self._send_packet(
					Jablotron.create_packet_get_system_info(JABLOTRON_SYSTEM_INFO_MODEL)
					+ Jablotron.create_packet_get_system_info(JABLOTRON_SYSTEM_INFO_HARDWARE_VERSION)
					+ Jablotron.create_packet_get_system_info(JABLOTRON_SYSTEM_INFO_FIRMWARE_VERSION)
				)
				time.sleep(1)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			self._central_unit = reader.result(TIMEOUT)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.error(format(ex))
			raise ServiceUnavailable

		finally:
			stop_event.set()
			thread_pool_executor.shutdown()

		if self._central_unit is None:
			raise ShouldNotHappen

	def _detect_sections_and_pg_outputs(self) -> None:
		stop_event = threading.Event()
		thread_pool_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

		def reader_thread() -> Optional[bytes]:
			states_packet = None

			stream = open(self._config[CONF_SERIAL_PORT], "rb")

			try:
				while not stop_event.is_set():
					# Don't parse - it's parsed later
					read_packet = stream.read(PACKET_READ_SIZE)
					if self._is_sections_states_packet(read_packet):
						states_packet = read_packet
						break

			finally:
				stream.close()

			return states_packet

		def writer_thread() -> None:
			while not stop_event.is_set():
				self._send_packet(Jablotron.create_packet_command(JABLOTRON_COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))
				time.sleep(1)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			raw_packet = reader.result(TIMEOUT)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.error(format(ex))
			raise ServiceUnavailable

		finally:
			stop_event.set()
			thread_pool_executor.shutdown()

		if raw_packet is None:
			raise ShouldNotHappen

		packets = Jablotron.get_packets_from_packet(raw_packet)

		for packet in packets:
			if Jablotron._is_sections_states_packet(packet):
				self._create_sections(packet)

			elif Jablotron._is_pg_outputs_states_packet(packet):
				self._parse_pg_outputs_states_packet(packet)

		# We have to create PG outputs even when no packet arrived
		self._create_pg_outputs()

	def _create_sections(self, packet: bytes) -> None:
		sections_states = Jablotron._parse_sections_states_packet(packet)

		for section, section_packet in sections_states.items():
			section_hass_device = Jablotron._create_section_hass_device(section)
			section_alarm_id = Jablotron._get_section_alarm_id(section)
			section_problem_sensor_id = Jablotron._get_section_problem_sensor_id(section)

			self._alarm_control_panels.append(JablotronAlarmControlPanel(
				self._central_unit,
				section_hass_device,
				section_alarm_id,
				Jablotron._get_section_alarm_name(section),
				section,
			))
			self._section_problem_sensors.append(JablotronControl(
				self._central_unit,
				section_hass_device,
				section_problem_sensor_id,
				Jablotron._get_section_problem_sensor_name(section),
			))

			section_state = Jablotron._parse_jablotron_section_state(section_packet)

			if not Jablotron._is_known_section_state(section_state):
				LOGGER.error("Unknown state packet for section {}: {}".format(section, Jablotron.format_packet_to_string(packet)))

			self._update_state(section_alarm_id, Jablotron._convert_jablotron_section_state_to_alarm_state(section_state), store_state=False)
			self._update_state(section_problem_sensor_id, Jablotron._convert_jablotron_section_state_to_problem_sensor_state(section_state), store_state=False)

	def _create_pg_outputs(self) -> None:
		if not self._has_pg_outputs():
			return

		for pg_output_number in range(1, self._config[CONF_NUMBER_OF_PG_OUTPUTS] + 1):
			pg_output_id = Jablotron._get_pg_output_id(pg_output_number)

			self._pg_outputs.append(JablotronProgrammableOutput(
				self._central_unit,
				pg_output_id,
				Jablotron._get_pg_output_name(pg_output_number),
				pg_output_number,
			))

			self._set_initial_state(pg_output_id, STATE_OFF)

	def _detect_devices(self) -> None:
		numbers_of_not_ignored_devices = self._get_numbers_of_not_ignored_devices()
		not_ignored_devices_count = len(numbers_of_not_ignored_devices)

		if not_ignored_devices_count == 0:
			return

		if len(self._devices_data.items()) == not_ignored_devices_count:
			items = list(self._devices_data.values())

			if DEVICE_DATA_SIGNAL_STRENGTH in items[0]:
				# Latest version with signal strength
				return

		stop_event = threading.Event()
		thread_pool_executor = ThreadPoolExecutor(max_workers=MAX_WORKERS)

		estimated_duration = math.ceil(not_ignored_devices_count / 10) + 1

		def reader_thread() -> Dict[str, bytes]:
			info_packets: Dict[str, bytes] = {}

			stream = open(self._config[CONF_SERIAL_PORT], "rb")

			try:
				while not stop_event.is_set():
					raw_packet = stream.read(PACKET_READ_SIZE)
					packets = Jablotron.get_packets_from_packet(raw_packet)

					for packet in packets:
						if self._is_device_info_packet(packet):
							info_packets[Jablotron._get_device_id(Jablotron.bytes_to_int(packet[3:4]))] = packet

					if len(info_packets.items()) == not_ignored_devices_count:
						break

			finally:
				stream.close()

			return info_packets

		def writer_thread() -> None:
			self._send_packet(Jablotron.create_packet_authorisation_code(self._config[CONF_PASSWORD]))

			while not stop_event.is_set():
				for number_of_not_ignored_device in numbers_of_not_ignored_devices:
					self._send_command(JABLOTRON_COMMAND_GET_DEVICE_INFO, Jablotron.int_to_bytes(number_of_not_ignored_device))

				time.sleep(estimated_duration)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			devices_info_packets = reader.result(estimated_duration * 2)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.error(format(ex))
			raise ServiceUnavailable

		finally:
			stop_event.set()
			thread_pool_executor.shutdown()

		if len(devices_info_packets.items()) != not_ignored_devices_count:
			raise ShouldNotHappen

		for device_id in devices_info_packets:
			device_connection = Jablotron._parse_device_connection_type_device_info_packet(devices_info_packets[device_id])

			self._devices_data[device_id] = {
				DEVICE_DATA_CONNECTION: device_connection,
				DEVICE_DATA_SIGNAL_STRENGTH: None,
				DEVICE_DATA_BATTERY_LEVEL: None,
			}

			if device_connection == DEVICE_CONNECTION_WIRELESS:
				battery_level = Jablotron._parse_device_battery_level_from_device_info_packet(devices_info_packets[device_id])

				signal_strength = Jablotron._parse_device_signal_strength_from_device_info_packet(devices_info_packets[device_id])
				self._devices_data[device_id][DEVICE_DATA_SIGNAL_STRENGTH] = signal_strength

				if battery_level is not None:
					self._devices_data[device_id][DEVICE_DATA_BATTERY_LEVEL] = battery_level
				else:
					LOGGER.debug("Unknown battery level packet of device {}: {}".format(
						Jablotron.bytes_to_int(devices_info_packets[device_id][3:4]),
						Jablotron.format_packet_to_string(devices_info_packets[device_id])),
					)

		self._store_devices_data()

	def _create_devices(self) -> None:
		numbers_of_not_ignored_devices = self._get_numbers_of_not_ignored_devices()

		if len(numbers_of_not_ignored_devices) == 0:
			return

		for device_number in numbers_of_not_ignored_devices:
			device_id = self._get_device_id(device_number)
			hass_device = self._create_device_hass_device(device_number)
			self._device_hass_devices[device_id] = hass_device

			device_sensor_id = Jablotron._get_device_sensor_id(device_number)
			device_problem_sensor_id = Jablotron._get_device_problem_sensor_id(device_number)
			device_signal_strength_sensor_id = Jablotron._get_device_signal_strength_sensor_id(device_number)
			device_battery_level_sensor_id = Jablotron._get_device_battery_level_sensor_id(device_number)
			type = self._get_device_type(device_number)

			if self._is_device_with_activity_sensor(device_number):
				self._device_sensors.append(JablotronDevice(
					self._central_unit,
					hass_device,
					device_sensor_id,
					Jablotron._get_device_sensor_name(type, device_number),
					type,
				))
				self._set_initial_state(device_sensor_id, STATE_OFF)

			self._device_problem_sensors.append(JablotronControl(
				self._central_unit,
				hass_device,
				device_problem_sensor_id,
				Jablotron._get_device_problem_sensor_name(type, device_number),
			))
			self._set_initial_state(device_problem_sensor_id, STATE_OFF)

			if self._is_wireless_device(device_number):
				self._device_signal_strength_sensors.append(JablotronControl(
					self._central_unit,
					hass_device,
					device_signal_strength_sensor_id,
					Jablotron._get_device_signal_strength_sensor_name(type, device_number),
				))
				self._set_initial_state(device_signal_strength_sensor_id, self._devices_data[device_id][DEVICE_DATA_SIGNAL_STRENGTH])

			if self._is_device_with_battery(device_number):
				self._device_battery_level_sensors.append(JablotronControl(
					self._central_unit,
					hass_device,
					device_battery_level_sensor_id,
					Jablotron._get_device_battery_level_sensor_name(type, device_number),
				))
				self._set_initial_state(device_battery_level_sensor_id, self._devices_data[device_id][DEVICE_DATA_BATTERY_LEVEL])

	def _create_lan_connection(self) -> None:
		if self._get_lan_connection_device_number() is None:
			return None

		id = self._get_lan_connection_id()

		self._lan_connection = JablotronControl(
			self._central_unit,
			None,
			id,
			self._get_lan_connection_name(),
		)

		self._set_initial_state(id, STATE_ON)

	def _create_gsm_sensors(self) -> None:
		if self._get_gsm_device_number() is None:
			return None

		signal_sensor_id = self._get_gsm_signal_sensor_id()
		signal_strength_sensor_id = self._get_gsm_signal_strength_sensor_id()

		self._gsm_signal_sensor = JablotronControl(
			self._central_unit,
			None,
			signal_sensor_id,
			self._get_gsm_signal_sensor_name(),
		)
		self._gsm_signal_strength_sensor = JablotronControl(
			self._central_unit,
			None,
			signal_strength_sensor_id,
			self._get_gsm_signal_strength_sensor_name(),
		)

		self._set_initial_state(signal_sensor_id, STATE_ON)
		self._set_initial_state(signal_strength_sensor_id, 100)

	def _has_pg_outputs(self) -> bool:
		if CONF_NUMBER_OF_PG_OUTPUTS not in self._config:
			return False

		return self._config[CONF_NUMBER_OF_PG_OUTPUTS] > 0

	def _read_packets(self) -> None:
		stream = open(self._config[CONF_SERIAL_PORT], "rb")
		last_restarted_at_hour = datetime.datetime.now().hour

		while not self._state_checker_stop_event.is_set():

			try:

				while True:

					actual_hour = datetime.datetime.now().hour
					if last_restarted_at_hour != actual_hour:
						stream.close()
						stream = open(self._config[CONF_SERIAL_PORT], "rb")
						last_restarted_at_hour = actual_hour

					self._state_checker_data_updating_event.clear()

					raw_packet = stream.read(PACKET_READ_SIZE)
					# LOGGER.debug(Jablotron.format_packet_to_string(raw_packet))

					self._state_checker_data_updating_event.set()

					if not raw_packet:
						self.last_update_success = False
						self._update_all_entities()
						break

					if self.last_update_success is False:
						self.last_update_success = True
						self._update_all_entities()

					packets = Jablotron.get_packets_from_packet(raw_packet)

					for packet in packets:
						if Jablotron._is_sections_states_packet(packet):
							in_service_mode = self.in_service_mode

							self._parse_section_states_packet(packet)

							if in_service_mode != self.in_service_mode:
								self._update_all_entities()

						elif Jablotron._is_pg_outputs_states_packet(packet):
							self._parse_pg_outputs_states_packet(packet)

						elif Jablotron._is_devices_states_packet(packet):
							self._parse_devices_states_packet(packet)

						elif Jablotron._is_device_state_packet(packet):
							self._parse_device_state_packet(packet)

						elif Jablotron._is_device_info_packet(packet):
							self._parse_device_info_packet(packet)

						elif Jablotron._is_login_error_packet(packet):
							# Login error - update section states to have actual states
							self._send_packet(Jablotron.create_packet_command(JABLOTRON_COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))

					break

			except Exception as ex:
				LOGGER.error("Read error: {}".format(format(ex)))
				self.last_update_success = False
				self._update_all_entities()

			time.sleep(0.5)

		stream.close()

	def _keepalive(self):
		counter = 0
		last_wireless_devices_update = datetime.datetime.now()

		while not self._state_checker_stop_event.is_set():
			if not self._state_checker_data_updating_event.wait(0.5):
				try:
					if counter == 0 and not self._is_alarm_active():
						self._send_packet(Jablotron.create_packet_keapalive(self._config[CONF_PASSWORD]))

						# Check wireless devices once a hour
						actual_time = datetime.datetime.now()
						time_since_last_update = actual_time - last_wireless_devices_update
						if time_since_last_update.total_seconds() > 3600:
							gsm_device_number = self._get_gsm_device_number()
							if gsm_device_number is not None:
								self._send_command(JABLOTRON_COMMAND_GET_DEVICE_INFO, Jablotron.int_to_bytes(gsm_device_number))

							for device_number in self._get_numbers_of_not_ignored_devices():
								if self._is_wireless_device(device_number):
									self._send_command(JABLOTRON_COMMAND_GET_DEVICE_INFO, Jablotron.int_to_bytes(device_number))

							last_wireless_devices_update = actual_time
					else:
						self._send_command(JABLOTRON_COMMAND_HEARTBEAT)
				except Exception as ex:
					LOGGER.error("Write error: {}".format(format(ex)))

				counter += 1
			else:
				time.sleep(1)

			if counter == 60:
				counter = 0

	def _send_command(self, type: bytes, data: Optional[bytes] = b"") -> None:
		self._send_packet(Jablotron.create_packet_command(type, data))

	def _send_request(self, type: bytes, data: bytes) -> None:
		self._send_packet(Jablotron.create_packet(type, data))

	def _send_packet(self, packet: bytes) -> None:
		stream = open(self._config[CONF_SERIAL_PORT], "wb")

		stream.write(packet)
		# LOGGER.debug(Jablotron.format_packet_to_string(packet))
		time.sleep(0.1)

		stream.close()

	def _is_alarm_active(self) -> bool:
		for alarm_control_panel in self._alarm_control_panels:
			section_alarm_id = Jablotron._get_section_alarm_id(alarm_control_panel.section)

			if (
				self.states[section_alarm_id] == STATE_ALARM_TRIGGERED
				or self.states[section_alarm_id] == STATE_ALARM_PENDING
			):
				return True

		return False

	def _get_device_type(self, number: int) -> str:
		return self._config[CONF_DEVICES][number - 1]

	def _is_device_ignored(self, number: int) -> bool:
		type = self._get_device_type(number)

		return type in [
			DEVICE_OTHER,
			DEVICE_EMPTY,
		]

	def _is_wireless_device(self, number: int):
		device_id = self._get_device_id(number)
		return self._devices_data[device_id][DEVICE_DATA_CONNECTION] == DEVICE_CONNECTION_WIRELESS

	def _is_device_with_battery(self, number: int):
		device_id = self._get_device_id(number)
		return self._devices_data[device_id][DEVICE_DATA_BATTERY_LEVEL] is not None

	def _is_device_with_activity_sensor(self, number: int) -> bool:
		type = self._get_device_type(number)

		return type not in [
			DEVICE_KEYPAD,
			DEVICE_SIREN_OUTDOOR,
		]

	def _parse_section_states_packet(self, packet: bytes) -> None:
		section_states = Jablotron._parse_sections_states_packet(packet)

		for section, section_packet in section_states.items():
			section_state = Jablotron._parse_jablotron_section_state(section_packet)

			if not Jablotron._is_known_section_state(section_state):
				LOGGER.error("Unknown state packet for section {}: {}".format(section, Jablotron.format_packet_to_string(packet)))

			if section_state["primary"] == JABLOTRON_SECTION_PRIMARY_STATE_SERVICE:
				# Service is for all sections - we can check only the first
				self.in_service_mode = True
				return

			self._update_state(
				Jablotron._get_section_alarm_id(section),
				Jablotron._convert_jablotron_section_state_to_alarm_state(section_state),
				store_state=False,
			)

			if (
				section_state["secondary"] == JABLOTRON_SECTION_SECONDARY_STATE_NOTHING
				or section_state["secondary"] == JABLOTRON_SECTION_SECONDARY_STATE_PROBLEM
			):
				self._update_state(
					Jablotron._get_section_problem_sensor_id(section),
					Jablotron._convert_jablotron_section_state_to_problem_sensor_state(section_state),
					store_state=False,
				)

		# No service mode found
		self.in_service_mode = False

	def _parse_device_info_packet(self, packet: bytes) -> None:
		device_number = Jablotron.bytes_to_int(packet[3:4])

		if device_number == self._get_gsm_device_number():
			self._parse_gsm_info_packet(packet)
			return

		device_connection = Jablotron._parse_device_connection_type_device_info_packet(packet)

		if device_connection == DEVICE_CONNECTION_WIRELESS:
			self._parse_wireless_device_info_packet(packet)

	def _parse_gsm_info_packet(self, packet: bytes) -> None:
		if packet[4:5] not in [b"\xa4", b"\xd5"]:
			LOGGER.error("Unknown info packet of GSM: {}".format(Jablotron.format_packet_to_string(packet)))
			return

		signal_strength_sensor_id = Jablotron._get_gsm_signal_strength_sensor_id()
		signal_strength = Jablotron.bytes_to_int(packet[5:6])

		self._update_state(signal_strength_sensor_id, signal_strength, store_state=True)

		self._store_devices_data()

	def _parse_wireless_device_info_packet(self, packet: bytes) -> None:
		device_number = Jablotron.bytes_to_int(packet[3:4])
		device_id = Jablotron._get_device_id(device_number)

		signal_strength = Jablotron._parse_device_signal_strength_from_device_info_packet(packet)
		signal_strength_sensor_id = Jablotron._get_device_signal_strength_sensor_id(device_number)

		self._update_state(signal_strength_sensor_id, signal_strength, store_state=True)
		self._devices_data[device_id][DEVICE_DATA_SIGNAL_STRENGTH] = signal_strength

		battery_level = Jablotron._parse_device_battery_level_from_device_info_packet(packet)

		if battery_level is None:
			LOGGER.error("Unknown battery level packet of device {}: {}".format(device_number, Jablotron.format_packet_to_string(packet)))
		else:
			battery_level_sensor_id = Jablotron._get_device_battery_level_sensor_id(device_number)

			self._update_state(battery_level_sensor_id, battery_level, store_state=True)
			self._device_hass_devices[device_id].battery_level = battery_level
			self._devices_data[device_id][DEVICE_DATA_BATTERY_LEVEL] = battery_level

		self._store_devices_data()

	def _parse_device_state_packet(self, packet: bytes) -> None:
		device_number = Jablotron._parse_device_number_from_state_packet(packet)

		if device_number == 0:
			LOGGER.debug("State packet of central unit: {}".format(Jablotron.format_packet_to_string(packet)))
			return

		if device_number == 250:
			# Mobile application
			return

		if device_number > 250:
			# Don't know
			return

		if device_number == self._get_lan_connection_device_number():
			self._parse_lan_connection_device_state_packet(packet)
			return

		if device_number == self._get_gsm_device_number():
			self._parse_gsm_device_state_packet(packet)
			return

		if device_number > self._config[CONF_NUMBER_OF_DEVICES]:
			LOGGER.debug("State packet of unknown device: {}".format(Jablotron.format_packet_to_string(packet)))
			return

		device_type = self._get_device_type(device_number)

		if self._is_device_ignored(device_number) or device_type == DEVICE_KEYPAD:
			LOGGER.debug("State packet of {}: {}".format(DEVICES[device_type].lower(), Jablotron.format_packet_to_string(packet)))
			return

		device_state = Jablotron._convert_jablotron_device_state_to_state(packet, device_number)

		if device_state is None:
			LOGGER.error("Unknown state packet of device {}: {}".format(device_number, Jablotron.format_packet_to_string(packet)))
			return

		if (
			self._is_device_with_activity_sensor(device_number)
			and Jablotron._is_device_state_packet_for_activity(packet)
		):
			self._update_state(
				Jablotron._get_device_sensor_id(device_number),
				device_state,
				store_state=False,
			)
		elif (
			Jablotron._is_device_state_packet_for_sabotage(packet)
			or Jablotron._is_device_state_packet_for_fault(packet)
		):
			self._update_state(
				Jablotron._get_device_problem_sensor_id(device_number),
				device_state,
				store_state=True,
			)
		else:
			LOGGER.error("Unknown state packet of device {}: {}".format(device_number, Jablotron.format_packet_to_string(packet)))

		if self._is_wireless_device(device_number):
			device_signal_strength = Jablotron.bytes_to_int(packet[10:11]) * JABLOTRON_SIGNAL_STRENGTH_STEP
			self._update_state(
				Jablotron._get_device_signal_strength_sensor_id(device_number),
				device_signal_strength,
				store_state=True,
			)

	def _parse_lan_connection_device_state_packet(self, packet: bytes) -> None:
		lan_connection_device_number = self._get_lan_connection_device_number()

		device_state = Jablotron._convert_jablotron_device_state_to_state(packet, lan_connection_device_number)

		if device_state is None:
			LOGGER.error("Unknown state packet of LAN connection: {}".format(Jablotron.format_packet_to_string(packet)))
			return

		self._update_state(
			Jablotron._get_lan_connection_id(),
			STATE_ON if device_state == STATE_OFF else STATE_OFF,
			store_state=True,
		)

	def _parse_gsm_device_state_packet(self, packet: bytes) -> None:
		gsm_device_number = self._get_gsm_device_number()

		device_state = Jablotron._convert_jablotron_device_state_to_state(packet, gsm_device_number)

		if device_state is None:
			LOGGER.error("Unknown state packet of GSM: {}".format(Jablotron.format_packet_to_string(packet)))
			return

		self._update_state(
			Jablotron._get_gsm_signal_sensor_id(),
			STATE_ON if device_state == STATE_OFF else STATE_OFF,
			store_state=True,
		)

	def _parse_devices_states_packet(self, packet: bytes) -> None:
		states_start = 2
		states_end = states_start + Jablotron.bytes_to_int(packet[1:2])

		# We need to ignore first packet
		states = Jablotron._hex_to_reverse_bin(packet[(states_start + 1):states_end])

		for device_number in self._get_numbers_of_not_ignored_devices():
			device_state = STATE_ON if states[device_number:(device_number + 1)] == "1" else STATE_OFF
			self._update_state(
				Jablotron._get_device_sensor_id(device_number),
				device_state,
				store_state=False,
			)

	def _parse_pg_outputs_states_packet(self, packet: bytes) -> None:
		if not self._has_pg_outputs():
			return

		states_start = 2
		states_end = states_start + Jablotron.bytes_to_int(packet[1:2])

		states = Jablotron._hex_to_bin(packet[states_start:states_end])

		for pg_output_number in range(1, self._config[CONF_NUMBER_OF_PG_OUTPUTS] + 1):
			pg_output_state = STATE_ON if states[(pg_output_number - 1):pg_output_number] == "1" else STATE_OFF

			self._update_state(
				Jablotron._get_pg_output_id(pg_output_number),
				pg_output_state,
				store_state=True,
			)

	def _get_lan_connection_device_number(self) -> Optional[int]:
		if self._central_unit.model in ["JA-101K-LAN", "JA-106K-3G"]:
			return 125

		if self._central_unit.model in ["JA-103K", "JA-103KRY", "JA-107K"]:
			return 233

		return None

	def _get_gsm_device_number(self) -> Optional[int]:
		if self._central_unit.model in ["JA-101K-LAN", "JA-106K-3G"]:
			return 127

		if self._central_unit.model in ["JA-103K", "JA-103KRY", "JA-107K"]:
			return 235

		return None

	def _get_numbers_of_not_ignored_devices(self) -> List[int]:
		numbers_of_not_ignored_devices = []

		for number in range(1, self._config[CONF_NUMBER_OF_DEVICES] + 1):
			if not self._is_device_ignored(number):
				numbers_of_not_ignored_devices.append(number)

		return numbers_of_not_ignored_devices

	def _set_initial_state(self, id: str, initial_state: StateType):
		if id in self.states:
			# Loaded from stored data
			return

		self._update_state(id, initial_state, store_state=False)

	def _update_state(self, id: str, state: StateType, store_state: bool) -> None:
		if store_state is True:
			self._store_state(id, state)

		if id in self.states and state == self.states[id]:
			return

		if id in self._entities:
			self._entities[id].update_state(state)
		else:
			self.states[id] = state

	def _store_state(self, id: str, state: StateType):
		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			self._stored_data[serial_port] = {}

		if STORAGE_STATES_KEY not in self._stored_data[serial_port]:
			self._stored_data[serial_port][STORAGE_STATES_KEY] = {}

		if (
			id in self._stored_data[serial_port][STORAGE_STATES_KEY]
			and self._stored_data[serial_port][STORAGE_STATES_KEY][id] == state
		):
			return

		self._stored_data[serial_port][STORAGE_STATES_KEY][id] = state
		self._store.async_delay_save(self._data_to_store)

	def _store_devices_data(self):
		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			self._stored_data[serial_port] = {}

		self._stored_data[serial_port][STORAGE_DEVICES_KEY] = self._devices_data
		self._store.async_delay_save(self._data_to_store)

	def _create_device_hass_device(self, device_number: int) -> JablotronHassDevice:
		device_id = Jablotron._get_device_id(device_number)
		device_type = self._get_device_type(device_number)

		battery_level: Optional[int] = None
		if self._is_device_with_battery(device_number):
			battery_level = self._devices_data[device_id][DEVICE_DATA_BATTERY_LEVEL]

		return JablotronHassDevice(
			"device_{}".format(device_number),
			"{} (device {})".format(DEVICES[device_type], device_number),
			battery_level,
		)

	@core.callback
	def _data_to_store(self) -> dict:
		return self._stored_data

	@staticmethod
	def _is_sections_states_packet(packet: bytes) -> bool:
		return packet[:1] == JABLOTRON_PACKET_SECTIONS_STATES

	@staticmethod
	def _is_login_error_packet(packet: bytes) -> bool:
		if (
			packet[:1] == JABLOTRON_PACKET_UI_CONTROL
			and packet[2:3] == b"\x1b"
			and packet[3:4] == b"\x03"
		):
			return True

		return False

	@staticmethod
	def _is_pg_outputs_states_packet(packet: bytes) -> bool:
		return packet[:1] == JABLOTRON_PACKET_PG_OUTPUTS_STATES

	@staticmethod
	def _is_devices_states_packet(packet: bytes) -> bool:
		return packet[:1] == JABLOTRON_PACKET_DEVICES_STATES

	@staticmethod
	def _is_device_info_packet(packet: bytes) -> bool:
		return packet[:1] == JABLOTRON_PACKET_COMMAND and packet[2:3] == JABLOTRON_COMMAND_RESPONSE_DEVICE_INFO

	@staticmethod
	def _is_device_state_packet(packet: bytes) -> bool:
		return packet[:1] == JABLOTRON_PACKET_DEVICE_STATE

	@staticmethod
	def _is_device_state_packet_for_activity(packet: bytes) -> bool:
		return packet[2:3] in JABLOTRON_PACKETS_DEVICE_ACTIVITY

	@staticmethod
	def _is_device_state_packet_for_sabotage(packet: bytes) -> bool:
		return Jablotron.bytes_to_int(packet[2:3]) % 128 == 6

	@staticmethod
	def _is_device_state_packet_for_fault(packet: bytes) -> bool:
		return Jablotron.bytes_to_int(packet[2:3]) % 128 == 7

	@staticmethod
	def _parse_sections_states_packet(packet: bytes) -> Dict[int, bytes]:
		section_states = {}

		for section in range(1, MAX_SECTIONS + 1):
			state_offset = section * 2
			state = packet[state_offset:(state_offset + 2)]

			# Unused section
			if state == b"\x07\x00":
				break

			section_states[section] = state

		return section_states

	@staticmethod
	def _parse_device_connection_type_device_info_packet(packet: bytes) -> str:
		packet_length = Jablotron.bytes_to_int(packet[1:2])
		return DEVICE_CONNECTION_WIRELESS if packet_length == 9 else DEVICE_CONNECTION_WIRED

	@staticmethod
	def _parse_device_signal_strength_from_device_info_packet(packet: bytes) -> Optional[int]:
		number = Jablotron.bytes_to_int(packet[9:10])
		return (number & 0x1f) * JABLOTRON_SIGNAL_STRENGTH_STEP

	@staticmethod
	def _parse_device_battery_level_from_device_info_packet(packet: bytes) -> Optional[int]:
		battery_level = Jablotron.bytes_to_int(packet[10:11])

		if battery_level > 10:
			return None

		return battery_level * JABLOTRON_BATTERY_LEVEL_STEP

	@staticmethod
	def _parse_device_number_from_state_packet(packet: bytes) -> int:
		return int(Jablotron.bytes_to_int(packet[4:6]) / 64)

	@staticmethod
	def _convert_jablotron_device_state_to_state(packet: bytes, device_number: int) -> Optional[str]:
		state = Jablotron.bytes_to_int(packet[3:4])

		if device_number <= 36:
			high_device_number_offset = 0
		elif device_number <= 96:
			high_device_number_offset = -64
		else:
			high_device_number_offset = -128

		device_states_offset = ((device_number + high_device_number_offset) * 4) + 104

		on_state = device_states_offset
		on_state_2 = device_states_offset + 1
		off_state = device_states_offset + 2
		off_state_2 = device_states_offset + 3

		if state == off_state or state == off_state_2:
			return STATE_OFF

		if state == on_state or state == on_state_2:
			return STATE_ON

		return None

	@staticmethod
	def _hex_to_bin(hex):
		dec = Jablotron.bytes_to_int(hex)
		bin_dec = bin(dec)
		bin_string = bin_dec[2:]
		return bin_string.zfill(len(hex) * 8)

	@staticmethod
	def _hex_to_reverse_bin(hex):
		bin_string = Jablotron._hex_to_bin(hex)
		return bin_string[::-1]

	@staticmethod
	def _get_device_id(device_number: int) -> str:
		return "device_{}".format(device_number)

	@staticmethod
	def _create_section_hass_device(section: int) -> JablotronHassDevice:
		return JablotronHassDevice(
			"section_{}".format(section),
			"Section {}".format(section),
		)

	@staticmethod
	def _get_section_alarm_id(section: int) -> str:
		return "section_{}".format(section)

	@staticmethod
	def _get_section_alarm_name(section: int) -> str:
		return "Section {}".format(section)

	@staticmethod
	def _get_section_problem_sensor_id(section: int) -> str:
		return "section_problem_sensor_{}".format(section)

	@staticmethod
	def _get_section_problem_sensor_name(section: int) -> str:
		return "Problem of section {}".format(section)

	@staticmethod
	def _get_device_sensor_id(device_number: int) -> str:
		return "device_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_sensor_name(device_type: str, device_number: int) -> str:
		return "{} (device {})".format(DEVICES[device_type], device_number)

	@staticmethod
	def _get_device_problem_sensor_id(device_number: int) -> str:
		return "device_problem_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_signal_strength_sensor_id(device_number: int) -> str:
		return "device_signal_strength_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_battery_level_sensor_id(device_number: int) -> str:
		return "device_battery_level_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_problem_sensor_name(device_type: str, device_number: int) -> str:
		return "Problem of {} (device {})".format(DEVICES[device_type].lower(), device_number)

	@staticmethod
	def _get_device_signal_strength_sensor_name(device_type: str, device_number: int) -> str:
		return "Signal strength of {} (device {})".format(DEVICES[device_type].lower(), device_number)

	@staticmethod
	def _get_device_battery_level_sensor_name(device_type: str, device_number: int) -> str:
		return "Battery level of {} (device {})".format(DEVICES[device_type].lower(), device_number)

	@staticmethod
	def _get_lan_connection_id() -> str:
		return "lan"

	@staticmethod
	def _get_lan_connection_name() -> str:
		return "LAN connection"

	@staticmethod
	def _get_gsm_signal_sensor_id() -> str:
		return "gsm_signal_sensor"

	@staticmethod
	def _get_gsm_signal_sensor_name() -> str:
		return "GSM signal"

	@staticmethod
	def _get_gsm_signal_strength_sensor_id() -> str:
		return "gsm_signal_strength_sensor"

	@staticmethod
	def _get_gsm_signal_strength_sensor_name() -> str:
		return "Signal strength of GSM"

	@staticmethod
	def _get_pg_output_id(pg_output_number: int) -> str:
		return "pg_output_{}".format(pg_output_number)

	@staticmethod
	def _get_pg_output_name(pg_output_number: int) -> str:
		return "PG output {}".format(pg_output_number)

	@staticmethod
	def _is_known_section_state(state: Dict[str, int]) -> bool:
		return (
			state["primary"] in JABLOTRON_SECTION_PRIMARY_STATES
			and state["secondary"] in JABLOTRON_SECTION_SECONDARY_STATES
			and state["tertiary"] in JABLOTRON_SECTION_TERTIARY_STATES
		)

	@staticmethod
	def _convert_jablotron_section_state_to_alarm_state(state: Dict[str, int]) -> str:
		if (
			state["primary"] == JABLOTRON_SECTION_PRIMARY_STATE_TRIGGERED
			or state["secondary"] == JABLOTRON_SECTION_SECONDARY_STATE_TRIGGERED
		):
			return STATE_ALARM_TRIGGERED

		if state["secondary"] == JABLOTRON_SECTION_SECONDARY_STATE_ARMING:
			return STATE_ALARM_ARMING

		if state["secondary"] == JABLOTRON_SECTION_SECONDARY_STATE_PENDING:
			return STATE_ALARM_PENDING

		if state["primary"] == JABLOTRON_SECTION_PRIMARY_STATE_ARMED_FULL:
			if state["tertiary"] == JABLOTRON_SECTION_TERTIARY_STATE_ON:
				return STATE_ALARM_TRIGGERED
			else:
				return STATE_ALARM_ARMED_AWAY

		if state["primary"] == JABLOTRON_SECTION_PRIMARY_STATE_ARMED_PARTIALLY:
			return STATE_ALARM_ARMED_NIGHT

		return STATE_ALARM_DISARMED

	@staticmethod
	def _convert_jablotron_section_state_to_problem_sensor_state(state: Dict[str, int]) -> str:
		return STATE_ON if state["secondary"] == JABLOTRON_SECTION_SECONDARY_STATE_PROBLEM else STATE_OFF

	@staticmethod
	def _parse_jablotron_section_state(packet: bytes) -> Dict[str, int]:
		first_number = Jablotron.bytes_to_int(packet[0:1])
		second_number = Jablotron.bytes_to_int(packet[1:2])

		primary_state = first_number % 16
		secondary_state = int((first_number - primary_state) / 16)
		tertiary_state = second_number % 16

		return {
			"primary": primary_state,
			"secondary": secondary_state,
			"tertiary": tertiary_state,
		}

	@staticmethod
	def get_packets_from_packet(packet: bytes) -> List[bytes]:
		packets = []

		start = 0
		while start < len(packet):
			if packet[start:(start + 1)] == b"\x00":
				break

			length = Jablotron.bytes_to_int(packet[(start + 1):(start + 2)])
			end = start + length + 2

			packets.append(packet[start:end])

			start = end

		return packets

	@staticmethod
	def decode_system_info_packet(packet: bytes) -> str:
		info = ""

		for i in range(3, len(packet)):
			letter = packet[i:(i + 1)]

			if letter == b"\x00":
				break

			info += letter.decode()

		return info

	@staticmethod
	def format_packet_to_string(packet: bytes) -> str:
		return str(binascii.hexlify(packet), "utf-8")

	@staticmethod
	def bytes_to_int(packet: bytes) -> int:
		return int.from_bytes(packet, byteorder=sys.byteorder)

	@staticmethod
	def int_to_bytes(number: int) -> bytes:
		return int.to_bytes(number, 1, byteorder=sys.byteorder)

	@staticmethod
	def create_packet(type: bytes, data: bytes) -> bytes:
		return type + Jablotron.int_to_bytes(len(data)) + data

	@staticmethod
	def create_packet_get_system_info(info_type: int) -> bytes:
		return Jablotron.create_packet(JABLOTRON_PACKET_GET_SYSTEM_INFO, Jablotron.int_to_bytes(info_type))

	@staticmethod
	def create_packet_command(type: bytes, data: Optional[bytes] = b"") -> bytes:
		return Jablotron.create_packet(JABLOTRON_PACKET_COMMAND, type + data)

	@staticmethod
	def create_packet_ui_control(type: bytes, data: Optional[bytes] = b"") -> bytes:
		return Jablotron.create_packet(JABLOTRON_PACKET_UI_CONTROL, type + data)

	@staticmethod
	def create_packet_enable_device_states() -> bytes:
		return Jablotron.create_packet_command(JABLOTRON_COMMAND_ENABLE_DEVICE_STATE_PACKETS, Jablotron.int_to_bytes(JABLOTRON_TIMEOUT_FOR_DEVICE_STATE_PACKETS))

	@staticmethod
	def create_packet_authorisation_code(code: str) -> bytes:
		code_packet = b"\x39\x39\x39"

		for i in range(0, 4):
			j = i + 4

			first_number = code[j:(j + 1)]
			second_number = code[i:(i + 1)]

			if first_number == "":
				code_number = 48 + int(second_number)
			else:
				code_number = int(f"{first_number}{second_number}", 16)

			code_packet += Jablotron.int_to_bytes(code_number)

		return Jablotron.create_packet_ui_control(JABLOTRON_UI_CONTROL_AUTHORISATION_CODE, code_packet)

	@staticmethod
	def create_packet_keapalive(code: str) -> bytes:
		return Jablotron.create_packet_authorisation_code(code) + Jablotron.create_packet_enable_device_states()


class JablotronEntity(Entity):

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
		if self._jablotron.in_service_mode is True:
			return False

		return self._jablotron.last_update_success

	@property
	def device_info(self) -> Optional[Dict[str, Any]]:
		if self._control.hass_device is None:
			return {
				"manufacturer": "Jablotron",
				"identifiers": {(DOMAIN, self._control.central_unit.serial_port)},
			}

		return {
			"manufacturer": "Jablotron",
			"identifiers": {(DOMAIN, self._control.hass_device.id)},
			"name": self._control.hass_device.name,
			"via_device": (DOMAIN, self._control.central_unit.serial_port),
		}

	@property
	def device_state_attributes(self) -> Optional[Dict[str, Any]]:
		if self._control.hass_device is None:
			return None

		if self._control.hass_device.battery_level is not None:
			return {
				ATTR_BATTERY_LEVEL: self._control.hass_device.battery_level,
			}

		return None

	@property
	def name(self) -> str:
		return self._control.name

	@property
	def unique_id(self) -> str:
		return "{}.{}.{}".format(DOMAIN, self._control.central_unit.serial_port, self._control.id)

	async def async_added_to_hass(self) -> None:
		self._jablotron.substribe_entity_for_updates(self._control.id, self)

	def update_state(self, state: StateType) -> None:
		self._jablotron.states[self._control.id] = state
		self.async_write_ha_state()

	@property
	def _state(self) -> str:
		return self._jablotron.states[self._control.id]
