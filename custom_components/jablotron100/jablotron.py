from __future__ import annotations

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
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import Entity
from homeassistant.helpers.typing import StateType
from homeassistant.helpers import entity_registry as er
import math
import sys
import threading
import time
from typing import Any, Dict, Final, List
from .const import (
	BATTERY_LEVELS_TO_IGNORE,
	BATTERY_LEVEL_STEP,
	CODE_MIN_LENGTH,
	COMMAND_ENABLE_DEVICE_STATE_PACKETS,
	COMMAND_GET_DEVICE_STATUS,
	COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES,
	COMMAND_HEARTBEAT,
	COMMAND_RESPONSE_DEVICE_STATUS,
	CONF_DEVICES,
	CONF_ENABLE_DEBUGGING,
	CONF_LOG_ALL_INCOMING_PACKETS,
	CONF_LOG_ALL_OUTCOMING_PACKETS,
	CONF_LOG_DEVICES_PACKETS,
	CONF_LOG_PG_OUTPUTS_PACKETS,
	CONF_LOG_SECTIONS_PACKETS,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_REQUIRE_CODE_TO_ARM,
	CONF_REQUIRE_CODE_TO_DISARM,
	CONF_SERIAL_PORT,
	DEFAULT_CONF_ENABLE_DEBUGGING,
	DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
	DEVICE_INFO_KNOWN_SUBPACKETS,
	DEVICE_INFO_KNOWN_TYPES,
	DEVICE_INFO_SUBPACKET_REQUESTED,
	DEVICE_INFO_TYPE_INPUT_EXTENDED,
	DEVICE_INFO_TYPE_INPUT_VALUE,
	DEVICE_INFO_TYPE_POWER,
	DEVICE_INFO_TYPE_PULSE,
	DEVICE_INFO_TYPE_SMOKE,
	DEVICE_PACKET_TYPE_FAULT,
	DEVICE_PACKET_TYPE_HEARTBEAT,
	DEVICE_PACKET_TYPE_POWER_SUPPLY_FAULT,
	DEVICE_PACKET_TYPE_SABOTAGE,
	DIAGNOSTICS_COMMAND_GET_INFO,
	DIAGNOSTICS_OFF,
	DIAGNOSTICS_ON,
	DOMAIN,
	DeviceConnection,
	DeviceData,
	DeviceNumber,
	DeviceType,
	EVENT_WRONG_CODE,
	EntityType,
	LOGGER,
	MAX_SECTIONS,
	PACKET_COMMAND,
	PACKET_DEVICES_SECTIONS,
	PACKET_DEVICES_STATES,
	PACKET_DEVICE_INFO,
	PACKET_DEVICE_STATE,
	PACKET_DIAGNOSTICS,
	PACKET_DIAGNOSTICS_COMMAND,
	PACKET_GET_DEVICES_SECTIONS,
	PACKET_GET_SYSTEM_INFO,
	PACKET_PG_OUTPUTS_STATES,
	PACKET_SECTIONS_STATES,
	PACKET_SYSTEM_INFO,
	PACKET_UI_CONTROL,
	PG_OUTPUT_TURN_OFF,
	PG_OUTPUT_TURN_ON,
	SECTION_PRIMARY_STATE_ARMED_FULL,
	SECTION_PRIMARY_STATE_ARMED_PARTIALLY,
	SECTION_PRIMARY_STATE_BLOCKED,
	SECTION_PRIMARY_STATE_SERVICE,
	SIGNAL_STRENGTH_STEP,
	STREAM_MAX_WORKERS,
	STREAM_PACKET_SIZE,
	STREAM_TIMEOUT,
	SYSTEM_INFO_FIRMWARE_VERSION,
	SYSTEM_INFO_HARDWARE_VERSION,
	SYSTEM_INFO_MODEL,
	TIMEOUT_FOR_DEVICE_STATE_PACKETS,
	UI_CONTROL_AUTHORISATION_CODE,
	UI_CONTROL_AUTHORISATION_END,
	UI_CONTROL_MODIFY_SECTION,
	UI_CONTROL_TOGGLE_PG_OUTPUT,
)
from .errors import (
	ServiceUnavailable,
	ShouldNotHappen,
	InvalidBatteryLevel,
)

STORAGE_VERSION: Final = 1
STORAGE_STATES_KEY: Final = "states"
STORAGE_DEVICES_KEY: Final = "devices"


class JablotronCentralUnit:

	def __init__(self, serial_port: str, model: str, hardware_version: str, firmware_version: str):
		self.serial_port: str = serial_port
		self.model: str = model
		self.hardware_version: str = hardware_version
		self.firmware_version: str = firmware_version


class JablotronHassDevice:

	def __init__(self, id: str, name: str, battery_level: int | None = None):
		self.id: str = id
		self.name: str = name
		self.battery_level: int | None = battery_level


class JablotronControl:

	def __init__(self, central_unit: JablotronCentralUnit, hass_device: JablotronHassDevice | None, id: str, name: str):
		self.central_unit: JablotronCentralUnit = central_unit
		self.hass_device: JablotronHassDevice | None = hass_device
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

	def __init__(self, hass: core.HomeAssistant, config_entry_id: str, config: Dict[str, Any], options: Dict[str, Any]) -> None:
		self._hass: core.HomeAssistant = hass
		self._config_entry_id: str = config_entry_id
		self._config: Dict[str, Any] = config
		self._options: Dict[str, Any] = options

		self._central_unit: JablotronCentralUnit | None = None
		self._device_hass_devices: Dict[str, JablotronHassDevice] = {}

		self.entities: Dict[EntityType, Dict[str, JablotronControl]] = {
			EntityType.ALARM_CONTROL_PANEL: {},
			EntityType.BATTERY_LEVEL: {},
			EntityType.CURRENT: {},
			EntityType.DEVICE_STATE: {},
			EntityType.FIRE: {},
			EntityType.GSM_SIGNAL: {},
			EntityType.IP: {},
			EntityType.LAN_CONNECTION: {},
			EntityType.PULSE: {},
			EntityType.PROBLEM: {},
			EntityType.PROGRAMMABLE_OUTPUT: {},
			EntityType.SIGNAL_STRENGTH: {},
			EntityType.TEMPERATURE: {},
			EntityType.VOLTAGE: {},
		}
		self.entities_states: Dict[str, StateType] = {}
		self.hass_entities: Dict[str, JablotronEntity] = {}

		self._stream_thread_pool_executor: ThreadPoolExecutor | None = None
		self._stream_stop_event: threading.Event = threading.Event()
		self._stream_data_updating_event: threading.Event = threading.Event()
		self._stream_diagnostics_event: threading.Event = threading.Event()

		self._store: storage.Store = storage.Store(hass, STORAGE_VERSION, DOMAIN)
		self._stored_data: dict | None = None

		self._devices_data: Dict[str, Dict[DeviceData, str | int | None]] = {}

		self.last_update_success: bool = False
		self.in_service_mode = False

		self._last_active_user: int | None = None
		self._successful_login: bool = True

	def signal_entities_added(self) -> str:
		return "{}_{}_entities_added".format(DOMAIN, self._config_entry_id)

	async def update_config_and_options(self, config: Dict[str, Any], options: Dict[str, Any]) -> None:
		self._config = config
		self._options = options

		await self._detect_and_create_devices_and_sections_and_pg_outputs()

		self._update_all_hass_entities()

	def is_code_required_for_disarm(self) -> bool:
		return self._options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM)

	def is_code_required_for_arm(self) -> bool:
		return self._options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM)

	def code_contains_asterisk(self) -> bool:
		return self._config[CONF_PASSWORD].find("*") != -1

	def last_active_user(self) -> int | None:
		return self._last_active_user

	async def initialize(self) -> None:
		def shutdown_event(_):
			self.shutdown()

		self._hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, shutdown_event)

		await self._load_stored_data()

		self._detect_central_unit()
		await self._detect_and_create_devices_and_sections_and_pg_outputs()
		self._create_central_unit_sensors()
		self._create_lan_connection()
		self._create_gsm_sensor()

		# Initialize stream threads
		self._stream_thread_pool_executor = ThreadPoolExecutor(max_workers=STREAM_MAX_WORKERS)
		self._stream_thread_pool_executor.submit(self._read_packets)
		self._stream_thread_pool_executor.submit(self._keepalive)

		self.last_update_success = True

	async def _detect_and_create_devices_and_sections_and_pg_outputs(self):
		self._detect_devices()
		await self._create_devices()
		# We need to detect devices first
		self._detect_sections_and_pg_outputs()

	def central_unit(self) -> JablotronCentralUnit:
		return self._central_unit

	def shutdown_and_clean(self) -> None:
		self.shutdown()

		serial_port = self._config[CONF_SERIAL_PORT]
		del self._stored_data[serial_port]
		self._store.async_delay_save(self._data_to_store)

	def shutdown(self) -> None:
		self._stream_stop_event.set()

		if self._stream_thread_pool_executor is not None:
			self._stream_thread_pool_executor.shutdown(wait=False, cancel_futures=True)

	def substribe_hass_entity_for_updates(self, control_id: str, hass_entity: JablotronEntity) -> None:
		self.hass_entities[control_id] = hass_entity

	def modify_alarm_control_panel_section_state(self, section: int, state: str, code: str | None) -> None:
		if code is None:
			code = self._config[CONF_PASSWORD]

		if len(code) < CODE_MIN_LENGTH:
			self._login_error()
			# Update section states to have actual states
			self._send_packet(self.create_packet_command(COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))
			return

		int_packets = {
			STATE_ALARM_DISARMED: 143,
			STATE_ALARM_ARMED_AWAY: 159,
			STATE_ALARM_ARMED_NIGHT: 175,
		}

		# Reset
		self._successful_login = True

		if code != self._config[CONF_PASSWORD]:
			packets = [
				self.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
				self.create_packet_authorisation_code(code),
			]

			self._send_packets(packets)
			time.sleep(1)

		if self._successful_login is True:
			state_packet = self.int_to_bytes(int_packets[state] + section)
			self._send_packet(self.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, state_packet))

		after_packets = []

		if code != self._config[CONF_PASSWORD]:
			after_packets.append(self.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END))
			after_packets.extend(self.create_packets_keepalive(self._config[CONF_PASSWORD]))

		# Update states - should fix state when invalid code was inserted
		after_packets.append(self.create_packet_command(COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))

		self._send_packets(after_packets)

	def toggle_pg_output(self, pg_output_number: int, state: str) -> None:
		pg_output_number_packet = self.int_to_bytes(pg_output_number - 1)
		state_packet = self.int_to_bytes(PG_OUTPUT_TURN_ON if state == STATE_ON else PG_OUTPUT_TURN_OFF)

		packet = self.create_packet_ui_control(UI_CONTROL_TOGGLE_PG_OUTPUT, pg_output_number_packet + state_packet)

		self._send_packet(packet)

	def _update_all_hass_entities(self) -> None:
		for hass_entity in self.hass_entities.values():
			hass_entity.refresh_state()

	async def _load_stored_data(self) -> None:
		self._stored_data = await self._store.async_load()

		if self._stored_data is None:
			self._stored_data = {}

		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			return

		if STORAGE_STATES_KEY in self._stored_data[serial_port]:
			self.entities_states = copy.deepcopy(self._stored_data[serial_port][STORAGE_STATES_KEY])

		if STORAGE_DEVICES_KEY in self._stored_data[serial_port]:
			self._devices_data = copy.deepcopy(self._stored_data[serial_port][STORAGE_DEVICES_KEY])

	def _detect_central_unit(self) -> None:
		stop_event = threading.Event()
		thread_pool_executor = ThreadPoolExecutor(max_workers=STREAM_MAX_WORKERS)

		def reader_thread() -> JablotronCentralUnit | None:
			model = None
			hardware_version = None
			firmware_version = None

			stream = self._open_read_stream()

			try:
				while not stop_event.is_set():
					raw_packet = stream.read(STREAM_PACKET_SIZE)
					packets = self.get_packets_from_packet(raw_packet)

					for packet in packets:
						self._log_incoming_packet(packet)

						if packet[:1] != PACKET_SYSTEM_INFO:
							continue

						try:
							info_type = self.bytes_to_int(packet[2:3])
							if info_type == SYSTEM_INFO_MODEL:
								model = self.decode_system_info_packet(packet)
							elif info_type == SYSTEM_INFO_HARDWARE_VERSION:
								hardware_version = self.decode_system_info_packet(packet)
							elif info_type == SYSTEM_INFO_FIRMWARE_VERSION:
								firmware_version = self.decode_system_info_packet(packet)
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
				self._send_packets([
					self.create_packet_get_system_info(SYSTEM_INFO_MODEL),
					self.create_packet_get_system_info(SYSTEM_INFO_HARDWARE_VERSION),
					self.create_packet_get_system_info(SYSTEM_INFO_FIRMWARE_VERSION),
				])
				time.sleep(1)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			self._central_unit = reader.result(STREAM_TIMEOUT)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.error(format(ex))
			raise ServiceUnavailable

		finally:
			stop_event.set()
			thread_pool_executor.shutdown(wait=False, cancel_futures=True)

		if self._central_unit is None:
			raise ShouldNotHappen

		LOGGER.debug("Central unit: {} (hardware: {}, firmware: {})".format(self._central_unit.model, self._central_unit.hardware_version, self._central_unit.firmware_version))

	def _detect_sections_and_pg_outputs(self) -> None:
		stop_event = threading.Event()
		thread_pool_executor = ThreadPoolExecutor(max_workers=STREAM_MAX_WORKERS)

		def reader_thread() -> List[bytes] | None:
			states_packets = None

			stream = self._open_read_stream()

			try:
				while not stop_event.is_set():
					raw_packet = stream.read(STREAM_PACKET_SIZE)
					read_packets = self.get_packets_from_packet(raw_packet)
					for read_packet in read_packets:
						self._log_incoming_packet(read_packet)

						if self._is_sections_states_packet(read_packet):
							states_packets = read_packets
							break

					if states_packets is not None:
						break

			finally:
				stream.close()

			return states_packets

		def writer_thread() -> None:
			while not stop_event.is_set():
				self._send_packet(self.create_packet_command(COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))
				time.sleep(1)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			packets = reader.result(STREAM_TIMEOUT)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.error(format(ex))
			raise ServiceUnavailable

		finally:
			stop_event.set()
			thread_pool_executor.shutdown(wait=False, cancel_futures=True)

		if packets is None:
			raise ShouldNotHappen

		for packet in packets:
			if self._is_sections_states_packet(packet):
				self._create_sections(packet)

			elif self._is_pg_outputs_states_packet(packet):
				self._parse_pg_outputs_states_packet(packet)

		# We have to create PG outputs even when no packet arrived
		self._create_pg_outputs()

	def _create_sections(self, packet: bytes) -> None:
		sections_states = self._convert_sections_states_packet_to_sections_states(packet)

		for section, section_state in sections_states.items():
			self._create_section(section, section_state)

	def _create_section(self, section: int, section_state: Dict[str, int | bool]) -> bool:
		section_alarm_id = self._get_section_alarm_id(section)
		section_problem_sensor_id = self._get_section_problem_sensor_id(section)
		section_fire_sensor_id = self._get_section_fire_sensor_id(section)

		section_has_smoke_detector = self._is_smoke_detector_in_section(section)

		if (
			section_alarm_id in self.entities[EntityType.ALARM_CONTROL_PANEL]
			and section_problem_sensor_id in self.entities[EntityType.PROBLEM]
			and (not section_has_smoke_detector or section_fire_sensor_id in self.entities[EntityType.FIRE])
		):
			return False

		section_hass_device = self._create_section_hass_device(section)

		if section_alarm_id not in self.entities[EntityType.ALARM_CONTROL_PANEL]:
			self.entities[EntityType.ALARM_CONTROL_PANEL][section_alarm_id] = JablotronAlarmControlPanel(
				self._central_unit,
				section_hass_device,
				section_alarm_id,
				self._get_section_alarm_name(section),
				section,
			)
			self._set_entity_initial_state(section_alarm_id, self._convert_jablotron_section_state_to_alarm_state(section_state))

		self._add_entity(
			section_hass_device,
			EntityType.PROBLEM,
			section_problem_sensor_id,
			self._get_section_problem_sensor_name(section),
			self._convert_jablotron_section_state_to_problem_sensor_state(section_state),
		)

		if section_has_smoke_detector:
			self._add_entity(
				section_hass_device,
				EntityType.FIRE,
				section_fire_sensor_id,
				self._get_section_fire_sensor_name(section),
				self._convert_jablotron_section_state_to_fire_sensor_state(section_state),
			)

		return True

	def _create_pg_outputs(self) -> None:
		if not self._has_pg_outputs():
			return

		for pg_output_number in range(1, self._config[CONF_NUMBER_OF_PG_OUTPUTS] + 1):
			pg_output_id = self._get_pg_output_id(pg_output_number)

			if pg_output_id in self.entities[EntityType.PROGRAMMABLE_OUTPUT]:
				continue

			self.entities[EntityType.PROGRAMMABLE_OUTPUT][pg_output_id] = JablotronProgrammableOutput(
				self._central_unit,
				pg_output_id,
				self._get_pg_output_name(pg_output_number),
				pg_output_number,
			)

			self._set_entity_initial_state(pg_output_id, STATE_OFF)

	def _detect_devices(self) -> None:
		not_ignored_devices = self._get_not_ignored_devices()
		not_ignored_devices_count = len(not_ignored_devices)

		if not_ignored_devices_count == 0:
			return

		if len(self._devices_data.items()) == not_ignored_devices_count:
			items = list(self._devices_data.values())

			if DeviceData.SECTION in items[0]:
				# Latest version with section
				return

		stop_event = threading.Event()
		thread_pool_executor = ThreadPoolExecutor(max_workers=STREAM_MAX_WORKERS)

		estimated_duration = math.ceil(not_ignored_devices_count / 10) + 1
		expected_packets_count = not_ignored_devices_count + 1

		def reader_thread() -> List[bytes]:
			expected_packets = []

			stream = self._open_read_stream()

			try:
				while not stop_event.is_set():
					raw_packet = stream.read(STREAM_PACKET_SIZE)
					parsed_packets = self.get_packets_from_packet(raw_packet)

					for parsed_packet in parsed_packets:
						self._log_incoming_packet(parsed_packet)

						if (
							self._is_device_status_packet(parsed_packet)
							or self._is_devices_sections_packet(parsed_packet)
						):
							expected_packets.append(parsed_packet)

					if len(expected_packets) == expected_packets_count:
						break

			finally:
				stream.close()

			return expected_packets

		def writer_thread() -> None:
			self._send_packet(self.create_packet_authorisation_code(self._config[CONF_PASSWORD]))

			while not stop_event.is_set():
				packets_to_send = []

				for number_of_not_ignored_device in not_ignored_devices:
					packets_to_send.append(self.create_packet_device_info(number_of_not_ignored_device))

				packets_to_send.append(self.create_packet(
					PACKET_GET_DEVICES_SECTIONS,
					self.int_to_bytes(1) + self.int_to_bytes(max(not_ignored_devices)),
				))

				self._send_packets(packets_to_send)
				time.sleep(estimated_duration)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			packets = reader.result(estimated_duration * 2)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.error(format(ex))
			raise ServiceUnavailable

		finally:
			stop_event.set()
			thread_pool_executor.shutdown(wait=False, cancel_futures=True)

		if len(packets) != expected_packets_count:
			raise ShouldNotHappen

		devices_sections_packet = None

		for packet in packets:
			if self._is_device_status_packet(packet):
				device_id = self._get_device_id(self._parse_device_number_from_device_status_packet(packet))
				device_connection = self._parse_device_connection_type_from_device_status_packet(packet)

				self._devices_data[device_id] = {
					DeviceData.CONNECTION: device_connection,
					DeviceData.SIGNAL_STRENGTH: None,
					DeviceData.BATTERY_LEVEL: None,
					DeviceData.SECTION: None,
				}

				if device_connection == DeviceConnection.WIRELESS:
					battery_level = self._parse_device_battery_level_from_device_status_packet(packet)

					signal_strength = self._parse_device_signal_strength_from_device_status_packet(packet)
					self._devices_data[device_id][DeviceData.SIGNAL_STRENGTH] = signal_strength

					if battery_level is not None:
						self._devices_data[device_id][DeviceData.BATTERY_LEVEL] = battery_level
			else:
				devices_sections_packet = packet

		device_number = 0
		for packet_offset in range(3, len(devices_sections_packet)):
			sections_packet_binary = self._bytes_to_binary(devices_sections_packet[packet_offset:(packet_offset + 1)])

			for device_offset in (4, 0):
				device_number += 1
				device_id = self._get_device_id(device_number)

				if device_id in self._devices_data:
					self._devices_data[device_id][DeviceData.SECTION] = self.binary_to_int(sections_packet_binary[device_offset:(device_offset + 4)]) + 1

		self._store_devices_data()

	async def _create_devices(self) -> None:
		for device_number in range(1, self._config[CONF_NUMBER_OF_DEVICES] + 1):
			device_problem_sensor_id = self._get_device_problem_sensor_id(device_number)

			if self._is_device_ignored(device_number):
				# Remove problem sensor if device is ignored now
				await self._remove_entity(EntityType.PROBLEM, device_problem_sensor_id)
				continue

			device_id = self._get_device_id(device_number)
			device_type = self._get_device_type(device_number)

			if device_id not in self._device_hass_devices:
				self._device_hass_devices[device_id] = self._create_device_hass_device(device_number)

			hass_device = self._device_hass_devices[device_id]

			# Problem sensor
			self._add_entity(
				hass_device,
				EntityType.PROBLEM,
				device_problem_sensor_id,
				self._get_device_problem_sensor_name(device_number),
				STATE_OFF,
			)

			# State sensor
			device_state_sensor_id = self._get_device_state_sensor_id(device_number)
			if self._is_device_with_state(device_number):
				if device_state_sensor_id not in self.entities[EntityType.DEVICE_STATE]:
					self.entities[EntityType.DEVICE_STATE][device_state_sensor_id] = JablotronDevice(
						self._central_unit,
						hass_device,
						device_state_sensor_id,
						self._get_device_sensor_name(device_number),
						device_type,
					)
					self._set_entity_initial_state(device_state_sensor_id, STATE_OFF)
			else:
				await self._remove_entity(EntityType.DEVICE_STATE, device_state_sensor_id)

			# Signal strength sensor
			device_signal_strength_sensor_id = self._get_device_signal_strength_sensor_id(device_number)
			if self.is_wireless_device(device_number):
				self._add_entity(
					hass_device,
					EntityType.SIGNAL_STRENGTH,
					device_signal_strength_sensor_id,
					self._get_device_signal_strength_sensor_name(device_number),
					self._devices_data[device_id][DeviceData.SIGNAL_STRENGTH],
				)
			else:
				await self._remove_entity(EntityType.SIGNAL_STRENGTH, device_signal_strength_sensor_id)

			# Battery level sensor
			device_battery_level_sensor_id = self._get_device_battery_level_sensor_id(device_number)
			if self.is_device_with_battery(device_number):
				self._add_entity(
					hass_device,
					EntityType.BATTERY_LEVEL,
					device_battery_level_sensor_id,
					self._get_device_battery_level_sensor_name(device_number),
					self._devices_data[device_id][DeviceData.BATTERY_LEVEL],
				)
			else:
				await self._remove_entity(EntityType.BATTERY_LEVEL, device_battery_level_sensor_id)

			# Temperature sensor
			device_temperature_sensor_id = self._get_device_temperature_sensor_id(device_number)
			if device_type in (DeviceType.THERMOMETER, DeviceType.THERMOSTAT, DeviceType.SMOKE_DETECTOR):
				self._add_entity(
					hass_device,
					EntityType.TEMPERATURE,
					device_temperature_sensor_id,
					self._get_device_temperature_sensor_name(device_number),
				)
			else:
				await self._remove_entity(EntityType.TEMPERATURE, device_temperature_sensor_id)

			# Battery voltage sensors
			device_battery_standby_voltage_sensor_id = self._get_device_battery_standby_voltage_sensor_id(device_number)
			device_battery_load_voltage_sensor_id = self._get_device_battery_load_voltage_sensor_id(device_number)
			if device_type == DeviceType.SIREN_OUTDOOR:
				self._add_entity(
					hass_device,
					EntityType.VOLTAGE,
					device_battery_standby_voltage_sensor_id,
					self._get_device_battery_standby_voltage_sensor_name(device_number),
				)

				self._add_entity(
					hass_device,
					EntityType.VOLTAGE,
					device_battery_load_voltage_sensor_id,
					self._get_device_battery_load_voltage_sensor_name(device_number),
				)
			else:
				await self._remove_entity(EntityType.VOLTAGE, device_battery_standby_voltage_sensor_id)
				await self._remove_entity(EntityType.VOLTAGE, device_battery_load_voltage_sensor_id)

			# Pulses sensor
			device_pulse_sensor_id = self._get_device_pulse_sensor_id(device_number)
			if device_type == DeviceType.ELECTRICITY_METER_WITH_PULSE_OUTPUT:
				self._add_entity(
					hass_device,
					EntityType.PULSE,
					device_pulse_sensor_id,
					self._get_device_pulse_sensor_name(device_number),
				)
			else:
				await self._remove_entity(EntityType.PULSE, device_pulse_sensor_id)

	def _create_central_unit_sensors(self) -> None:
		self._add_entity(
			None,
			EntityType.BATTERY_LEVEL,
			self._get_device_battery_level_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			self._get_device_battery_level_sensor_name(DeviceNumber.CENTRAL_UNIT.value),
		)

		self._add_entity(
			None,
			EntityType.VOLTAGE,
			self._get_device_battery_standby_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			self._get_device_battery_standby_voltage_sensor_name(DeviceNumber.CENTRAL_UNIT.value),
		)

		self._add_entity(
			None,
			EntityType.VOLTAGE,
			self._get_device_battery_load_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			self._get_device_battery_load_voltage_sensor_name(DeviceNumber.CENTRAL_UNIT.value),
		)

		self._add_entity(
			None,
			EntityType.VOLTAGE,
			self._get_device_bus_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			self._get_device_bus_voltage_sensor_name(DeviceNumber.CENTRAL_UNIT.value),
		)

		self._add_entity(
			None,
			EntityType.CURRENT,
			self._get_device_bus_devices_loss_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			self._get_device_bus_devices_loss_sensor_name(DeviceNumber.CENTRAL_UNIT.value),
		)

	def _create_lan_connection(self) -> None:
		if self._get_lan_connection_device_number() is None:
			return None

		self._add_entity(
			None,
			EntityType.LAN_CONNECTION,
			self._get_lan_connection_id(),
			self._get_lan_connection_name(),
			STATE_ON,
		)

		self._add_entity(
			None,
			EntityType.IP,
			self._get_lan_connection_ip_id(),
			self._get_lan_connection_ip_name(),
		)

	def _create_gsm_sensor(self) -> None:
		if self._get_gsm_device_number() is None:
			return None

		self._add_entity(
			None,
			EntityType.GSM_SIGNAL,
			self._get_gsm_signal_sensor_id(),
			self._get_gsm_signal_sensor_name(),
			STATE_ON,
		)

		self._add_entity(
			None,
			EntityType.SIGNAL_STRENGTH,
			self._get_gsm_signal_strength_sensor_id(),
			self._get_gsm_signal_strength_sensor_name(),
			100,
		)

	def _force_devices_status_update(self) -> None:
		packets = []

		gsm_device_number = self._get_gsm_device_number()
		if gsm_device_number is not None:
			packets.append(self.create_packet_device_info(gsm_device_number))

		lan_connection_device_number = self._get_lan_connection_device_number()
		if lan_connection_device_number is not None:
			packets.append(self.create_packet_device_info(lan_connection_device_number))

		for device_number in self._get_not_ignored_devices():
			if self.is_wireless_device(device_number):
				packets.append(self.create_packet_device_info(device_number))

		if len(packets) > 0:
			self._send_packets(packets)

	def _force_devices_info_update(self) -> None:
		for device_number in self._get_not_ignored_devices():
			device_type = self._get_device_type(device_number)

			if device_type not in (DeviceType.THERMOMETER, DeviceType.THERMOSTAT, DeviceType.SMOKE_DETECTOR, DeviceType.SIREN_OUTDOOR):
				continue

			self._stream_diagnostics_event.clear()

			self._send_packets([
				self._create_packet_device_diagnostics_start(device_number),
				self._create_packet_device_diagnostics_force_info(device_number),
			])

			while not self._stream_diagnostics_event.wait(0.5):
				break

			self._send_packet(self._create_packet_device_diagnostics_end(device_number))

	def _has_pg_outputs(self) -> bool:
		if CONF_NUMBER_OF_PG_OUTPUTS not in self._config:
			return False

		return self._config[CONF_NUMBER_OF_PG_OUTPUTS] > 0

	def _login_error(self) -> None:
		self._hass.bus.fire(EVENT_WRONG_CODE)

	def _read_packets(self) -> None:
		stream = self._open_read_stream()
		last_restarted_at_hour = datetime.datetime.now().hour

		while not self._stream_stop_event.is_set():

			try:

				while True:

					actual_hour = datetime.datetime.now().hour
					if last_restarted_at_hour != actual_hour:
						stream.close()
						stream = self._open_read_stream()
						last_restarted_at_hour = actual_hour

					self._stream_data_updating_event.clear()

					raw_packet = stream.read(STREAM_PACKET_SIZE)

					self._stream_data_updating_event.set()

					if not raw_packet:
						self.last_update_success = False
						self._update_all_hass_entities()
						break

					if self.last_update_success is False:
						self.last_update_success = True
						self._update_all_hass_entities()

					packets = self.get_packets_from_packet(raw_packet)

					for packet in packets:
						self._log_incoming_packet(packet)

						if self._is_sections_states_packet(packet):
							in_service_mode = self.in_service_mode

							self._parse_sections_states_packet(packet)

							if in_service_mode != self.in_service_mode:
								self._update_all_hass_entities()

						elif self._is_pg_outputs_states_packet(packet):
							self._parse_pg_outputs_states_packet(packet)

						elif self._is_devices_states_packet(packet):
							self._parse_devices_states_packet(packet)

						elif self._is_device_state_packet(packet):
							self._parse_device_state_packet(packet)

						elif self._is_device_info_packet(packet):
							if self._is_requested_device_info_packet(packet):
								self._stream_diagnostics_event.set()

							self._parse_device_info_packet(packet)

						elif self._is_device_status_packet(packet):
							self._parse_device_status_packet(packet)

						elif self._is_login_error_packet(packet):
							self._successful_login = False
							self._last_active_user = None
							self._login_error()

					break

			except Exception as ex:
				LOGGER.error("Read error: {}".format(format(ex)))
				self.last_update_success = False
				self._update_all_hass_entities()

			time.sleep(0.5)

		stream.close()

	def _keepalive(self):
		counter = 0
		last_devices_update = None

		while not self._stream_stop_event.is_set():
			if not self._stream_data_updating_event.wait(0.5):
				try:
					if counter == 0 and not self._is_alarm_active():
						self._send_packets(self.create_packets_keepalive(self._config[CONF_PASSWORD]))

						# Check some devices once a hour (and on the start too)
						actual_time = datetime.datetime.now()
						if (
							last_devices_update is None
							or (actual_time - last_devices_update).total_seconds() > 3600
						):
							self._force_devices_status_update()
							self._force_devices_info_update()

							last_devices_update = actual_time
					else:
						self._send_packet(self.create_packet_command(COMMAND_HEARTBEAT))

				except Exception as ex:
					LOGGER.error("Write error: {}".format(format(ex)))

				counter += 1
			else:
				time.sleep(1)

			if counter == 60:
				counter = 0

	def _send_packets(self, batch: List[bytes]) -> None:
		batch_packet = b""
		for packet in batch:
			self._log_outcoming_packet(packet)

			if len(batch_packet) + len(packet) > STREAM_PACKET_SIZE:
				self._send_packet_by_stream(batch_packet)
				batch_packet = b""

			batch_packet += packet

		if batch_packet != b"":
			self._send_packet_by_stream(batch_packet)

	def _send_packet(self, packet: bytes) -> None:
		self._log_outcoming_packet(packet)
		self._send_packet_by_stream(packet)

	def _send_packet_by_stream(self, packet: bytes) -> None:
		stream = self._open_write_stream()

		stream.write(packet)

		stream.close()

	def _open_write_stream(self):
		return open(self._config[CONF_SERIAL_PORT], "wb", buffering=0)

	def _open_read_stream(self):
		return open(self._config[CONF_SERIAL_PORT], "rb", buffering=0)

	def _is_alarm_active(self) -> bool:
		for section_alarm_id in self.entities[EntityType.ALARM_CONTROL_PANEL]:
			if (
				self.entities_states[section_alarm_id] == STATE_ALARM_TRIGGERED
				or self.entities_states[section_alarm_id] == STATE_ALARM_PENDING
			):
				return True

		return False

	def _get_device_type(self, number: int) -> DeviceType:
		if number == DeviceNumber.CENTRAL_UNIT.value:
			return DeviceType.CENTRAL_UNIT

		return DeviceType(self._config[CONF_DEVICES][number - 1])

	def _get_device_name(self, number: int) -> str:
		return self._get_device_type(number).get_name()

	def _is_device_ignored(self, number: int) -> bool:
		device_type = self._get_device_type(number)

		return device_type in (
			DeviceType.OTHER,
			DeviceType.EMPTY,
		)

	def is_wireless_device(self, number: int) -> bool:
		device_id = self._get_device_id(number)

		if device_id not in self._devices_data:
			return False

		return self._devices_data[device_id][DeviceData.CONNECTION] == DeviceConnection.WIRELESS

	def is_device_with_battery(self, number: int) -> bool:
		if number == DeviceNumber.CENTRAL_UNIT.value:
			return True

		device_id = self._get_device_id(number)

		if device_id not in self._devices_data:
			return False

		return self._devices_data[device_id][DeviceData.BATTERY_LEVEL] is not None

	def get_device_section(self, number: int) -> int:
		device_id = self._get_device_id(number)

		return self._devices_data[device_id][DeviceData.SECTION]

	def _is_device_with_state(self, number: int) -> bool:
		device_type = self._get_device_type(number)

		return device_type not in (
			DeviceType.KEYPAD,
			DeviceType.SIREN_OUTDOOR,
			DeviceType.ELECTRICITY_METER_WITH_PULSE_OUTPUT,
			DeviceType.RADIO_MODULE,
		)

	def _parse_sections_states_packet(self, packet: bytes) -> None:
		sections_states = self._convert_sections_states_packet_to_sections_states(packet)

		for section, section_state in sections_states.items():
			if section_state["state"] == SECTION_PRIMARY_STATE_SERVICE:
				# Service is for all sections - we can check only the first
				self.in_service_mode = True
				return

			if self._create_section(section, section_state):
				async_dispatcher_send(self._hass, self.signal_entities_added())

			self._update_entity_state(
				self._get_section_alarm_id(section),
				self._convert_jablotron_section_state_to_alarm_state(section_state),
				store_state=False,
			)
			self._update_entity_state(
				self._get_section_problem_sensor_id(section),
				self._convert_jablotron_section_state_to_problem_sensor_state(section_state),
				store_state=False,
			)

			section_fire_sensor_id = self._get_section_fire_sensor_id(section)
			if section_fire_sensor_id in self.entities[EntityType.FIRE]:
				self._update_entity_state(
					section_fire_sensor_id,
					self._convert_jablotron_section_state_to_fire_sensor_state(section_state),
					store_state=False,
				)

		# No service mode found
		self.in_service_mode = False

	def _parse_device_status_packet(self, packet: bytes) -> None:
		device_number = self._parse_device_number_from_device_status_packet(packet)

		if device_number == self._get_gsm_device_number():
			self._parse_gsm_status_packet(packet)
			return

		if device_number == self._get_lan_connection_device_number():
			self._parse_lan_connection_status_packet(packet)
			return

		device_connection = self._parse_device_connection_type_from_device_status_packet(packet)

		if device_connection == DeviceConnection.WIRELESS:
			self._parse_wireless_device_status_packet(packet)

	def _parse_gsm_status_packet(self, packet: bytes) -> None:
		if packet[4:5] not in (b"\xa4", b"\xd5"):
			self._log_error_with_packet("Unknown status packet of GSM", packet)
			return

		signal_strength_sensor_id = self._get_gsm_signal_strength_sensor_id()
		signal_strength = self.bytes_to_int(packet[5:6])

		self._update_entity_state(signal_strength_sensor_id, signal_strength)

		self._store_devices_data()

	def _parse_lan_connection_status_packet(self, packet: bytes) -> None:
		lan_connection_ip_id = self._get_lan_connection_ip_id()

		ip_parts = []
		for packet_position in range(6, 10):
			ip_parts.append(str(self.bytes_to_int(packet[packet_position:(packet_position + 1)])))

		lan_ip = ".".join(ip_parts)

		self._update_entity_state(lan_connection_ip_id, lan_ip)

		self._store_devices_data()

	def _parse_wireless_device_status_packet(self, packet: bytes) -> None:
		device_number = self._parse_device_number_from_device_status_packet(packet)
		device_id = self._get_device_id(device_number)

		signal_strength = self._parse_device_signal_strength_from_device_status_packet(packet)
		signal_strength_sensor_id = self._get_device_signal_strength_sensor_id(device_number)

		self._update_entity_state(signal_strength_sensor_id, signal_strength)
		self._devices_data[device_id][DeviceData.SIGNAL_STRENGTH] = signal_strength

		battery_level = self._parse_device_battery_level_from_device_status_packet(packet)

		if battery_level is not None:
			battery_level_sensor_id = self._get_device_battery_level_sensor_id(device_number)

			self._update_entity_state(battery_level_sensor_id, battery_level)
			self._device_hass_devices[device_id].battery_level = battery_level
			self._devices_data[device_id][DeviceData.BATTERY_LEVEL] = battery_level

		self._store_devices_data()

	def _parse_device_state_packet(self, packet: bytes) -> None:
		device_number = self._parse_device_number_from_device_state_packet(packet)

		if device_number == DeviceNumber.CENTRAL_UNIT.value:
			self._log_debug_with_packet("State packet of central unit", packet)
			return

		if device_number in (DeviceNumber.MOBILE_APPLICATION.value, DeviceNumber.USB.value):
			self._set_last_active_user_from_device_state_packet(packet, device_number)
			return

		if device_number == self._get_lan_connection_device_number():
			self._parse_lan_connection_device_state_packet(packet)
			return

		if device_number == self._get_gsm_device_number():
			self._parse_gsm_device_state_packet(packet)
			return

		if device_number > self._config[CONF_NUMBER_OF_DEVICES]:
			self._log_error_with_packet("State packet of unknown device {}".format(device_number), packet)
			return

		device_type = self._get_device_type(device_number)

		if device_type == DeviceType.KEYPAD:
			self._set_last_active_user_from_device_state_packet(packet, device_number)
			return

		if self._is_device_ignored(device_number):
			self._log_debug_with_packet("State packet of {}".format(device_type.get_name().lower()), packet)
			return

		device_state = self._convert_jablotron_device_state_to_state(packet, device_number)

		if device_state is None:
			self._log_error_with_packet("Unknown state packet of device {}".format(device_number), packet)
			return

		packet_state_binary = self._bytes_to_binary(packet[2:3])
		packet_type = self.binary_to_int(packet_state_binary[4:])

		if packet_type == DEVICE_PACKET_TYPE_HEARTBEAT:
			# Ignore
			pass
		elif (
			self._is_device_with_state(device_number)
			and self._is_device_state_packet_for_state(packet_type)
		):
			self._update_entity_state(
				self._get_device_state_sensor_id(device_number),
				device_state,
				store_state=False,
			)
		elif self._is_device_state_packet_for_fault(packet_type):
			self._update_entity_state(
				self._get_device_problem_sensor_id(device_number),
				device_state,
			)
		else:
			self._log_error_with_packet("Unknown state packet of device {}".format(device_number), packet)

		if self.is_wireless_device(device_number):
			device_signal_strength = self.bytes_to_int(packet[10:11]) * SIGNAL_STRENGTH_STEP
			self._update_entity_state(
				self._get_device_signal_strength_sensor_id(device_number),
				device_signal_strength,
			)

	def _parse_device_info_packet(self, packet: bytes) -> None:
		device_number = self._parse_device_number_from_device_info_packet(packet)

		if device_number > self._config[CONF_NUMBER_OF_DEVICES]:
			self._log_error_with_packet("Info packet of unknown device {}".format(device_number), packet)
			return

		subpacket_type = packet[3:4]

		if subpacket_type not in DEVICE_INFO_KNOWN_SUBPACKETS:
			self._log_error_with_packet(
				"Unknown info subpacket type {} (device {})".format(self.format_packet_to_string(subpacket_type), device_number),
				packet,
			)
			return

		device_battery_level = self._parse_device_battery_level_from_device_info_packet(packet)
		if device_battery_level is not None:
			if not self.is_device_with_battery(device_number):
				self._add_battery_to_device(device_number, device_battery_level)

			self._update_entity_state(
				self._get_device_battery_level_sensor_id(device_number),
				device_battery_level,
			)

		if device_number == DeviceNumber.CENTRAL_UNIT.value:
			self._parse_central_unit_info_packet(packet)
		else:
			device_type = self._get_device_type(device_number)

			if device_type in (DeviceType.THERMOMETER, DeviceType.THERMOSTAT):
				self._parse_device_input_value_info_packet(packet, device_number)
			elif device_type == DeviceType.SMOKE_DETECTOR:
				self._parse_device_smoke_detector_info_packet(packet, device_number)
			elif device_type == DeviceType.SIREN_OUTDOOR:
				self._parse_device_siren_outdoor_info_packet(packet, device_number)
			elif device_type == DeviceType.ELECTRICITY_METER_WITH_PULSE_OUTPUT:
				self._parse_device_electricity_meter_with_pulse_info_packet(packet, device_number)
			elif device_type == DeviceType.RADIO_MODULE:
				self._log_debug_with_packet("Info packet of radio module", packet)

	def _parse_device_input_value_info_packet(self, packet: bytes, device_number: int) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_packet(packet)

		for info_packet in info_packets:
			info_packet_type = info_packet[0:1]

			if info_packet_type == DEVICE_INFO_TYPE_INPUT_VALUE:
				input_type = info_packet[1:2]

				# Temperature
				if input_type == b"\x00":
					modifier = Jablotron.bytes_to_int(info_packet[4:5])

					if modifier >= 128:
						modifier -= 256

					temperature = round((Jablotron.bytes_to_int(info_packet[3:4]) + (255 * modifier)) / 10, 1)

					self._update_entity_state(
						self._get_device_temperature_sensor_id(device_number),
						temperature,
					)
				else:
					self._log_error_with_packet(
						"Unknown input type {} of value info packet {} (device {})".format(Jablotron.format_packet_to_string(input_type), Jablotron.format_packet_to_string(info_packet), device_number),
						packet,
					)
			elif info_packet == DEVICE_INFO_TYPE_INPUT_EXTENDED:
				# Ignore
				pass
			else:
				self._log_error_with_packet(
					"Unexpected info packet {} (device {})".format(Jablotron.format_packet_to_string(info_packet), device_number),
					packet,
				)

	def _parse_device_smoke_detector_info_packet(self, packet: bytes, device_number: int) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_packet(packet)

		for info_packet in info_packets:
			info_packet_type = info_packet[0:1]

			if info_packet_type != DEVICE_INFO_TYPE_SMOKE:
				self._log_error_with_packet(
					"Unexpected info packet {} of smoke detector (device {})".format(Jablotron.format_packet_to_string(info_packet), device_number),
					packet,
				)
				continue

			self._update_entity_state(
				self._get_device_temperature_sensor_id(device_number),
				float(Jablotron.bytes_to_int(info_packet[1:2])),
			)

	def _parse_device_siren_outdoor_info_packet(self, packet: bytes, device_number: int) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_packet(packet)

		for info_packet in info_packets:
			info_packet_type = info_packet[0:1]

			if info_packet_type != DEVICE_INFO_TYPE_POWER:
				self._log_error_with_packet(
					"Unexpected info packet {} of outdoor siren (device {})".format(Jablotron.format_packet_to_string(info_packet), device_number),
					packet,
				)
				continue

			channel = info_packet[1:2]

			if channel == b"\x00":
				self._update_entity_state(
					self._get_device_battery_standby_voltage_sensor_id(device_number),
					self.bytes_to_float(info_packet[2:3]),
				)
			elif channel == b"\x01":
				self._update_entity_state(
					self._get_device_battery_load_voltage_sensor_id(device_number),
					self.bytes_to_float(info_packet[2:3]),
				)
			else:
				self._log_error_with_packet(
					"Unknown channel {} of power info packet {} of outdoor siren (device {})".format(Jablotron.format_packet_to_string(channel), Jablotron.format_packet_to_string(info_packet), device_number),
					packet,
				)

	def _parse_device_electricity_meter_with_pulse_info_packet(self, packet: bytes, device_number: int) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_packet(packet)

		info_packet_number = 0
		for info_packet in info_packets:
			info_packet_type = info_packet[0:1]
			info_packet_number += 1

			if info_packet_type != DEVICE_INFO_TYPE_PULSE:
				self._log_error_with_packet(
					"Unexpected info packet {} of electricity meter with pulse (device {})".format(Jablotron.format_packet_to_string(info_packet), device_number),
					packet,
				)
				continue

			# We parse only first pulse packet
			if info_packet_number == 1:
				pulses = self.bytes_to_int(info_packet[11:12]) + 255 * self.bytes_to_int(info_packet[12:13])

				self._update_entity_state(
					self._get_device_pulse_sensor_id(device_number),
					pulses,
				)

	def _parse_central_unit_info_packet(self, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_packet(packet)

		for info_packet in info_packets:
			info_packet_type = info_packet[0:1]

			if info_packet_type != DEVICE_INFO_TYPE_POWER:
				self._log_error_with_packet("Unexpected info packet {} of central unit".format(Jablotron.format_packet_to_string(info_packet)), packet)
				continue

			channel = info_packet[1:2]

			if channel == b"\x00":
				self._update_entity_state(
					self._get_device_battery_load_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
					self.bytes_to_float(info_packet[2:3]),
				)
			elif channel == b"\x10":
				self._update_entity_state(
					self._get_device_battery_standby_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
					self.bytes_to_float(info_packet[2:3]),
				)
			elif channel == b"\x11":
				# Battery in test
				pass
			elif channel == b"\x01":
				self._update_entity_state(
					self._get_device_bus_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
					self.bytes_to_float(info_packet[2:3]),
				)
				self._update_entity_state(
					self._get_device_bus_devices_loss_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
					self.bytes_to_int(info_packet[3:4]),
				)
			else:
				self._log_error_with_packet(
					"Unknown channel {} of power info packet {} of central unit".format(Jablotron.format_packet_to_string(channel), Jablotron.format_packet_to_string(info_packet)),
					packet,
				)

	def _parse_lan_connection_device_state_packet(self, packet: bytes) -> None:
		lan_connection_device_number = self._get_lan_connection_device_number()

		device_state = self._convert_jablotron_device_state_to_state(packet, lan_connection_device_number)

		if device_state is None:
			self._log_error_with_packet("Unknown state packet of LAN connection", packet)
			return

		self._update_entity_state(
			self._get_lan_connection_id(),
			STATE_ON if device_state == STATE_OFF else STATE_OFF,
		)

	def _parse_gsm_device_state_packet(self, packet: bytes) -> None:
		gsm_device_number = self._get_gsm_device_number()

		device_state = self._convert_jablotron_device_state_to_state(packet, gsm_device_number)

		if device_state is None:
			self._log_error_with_packet("Unknown state packet of GSM", packet)
			return

		self._update_entity_state(
			self._get_gsm_signal_sensor_id(),
			STATE_ON if device_state == STATE_OFF else STATE_OFF,
		)

	def _parse_devices_states_packet(self, packet: bytes) -> None:
		states_start = 2
		states_end = states_start + self.bytes_to_int(packet[1:2])

		# We need to ignore first packet
		states = self._bytes_to_reverse_binary(packet[(states_start + 1):states_end])

		for device_number in self._get_not_ignored_devices():
			device_state = STATE_ON if states[device_number:(device_number + 1)] == "1" else STATE_OFF
			self._update_entity_state(
				self._get_device_state_sensor_id(device_number),
				device_state,
				store_state=False,
			)

	def _parse_pg_outputs_states_packet(self, packet: bytes) -> None:
		if not self._has_pg_outputs():
			return

		states_start = 2
		states_end = states_start + self.bytes_to_int(packet[1:2])

		states = self._bytes_to_reverse_binary(packet[states_start:states_end])

		for index in range(0, self._config[CONF_NUMBER_OF_PG_OUTPUTS]):
			pg_output_number = index + 1
			pg_output_state = STATE_ON if states[index:(index + 1)] == "1" else STATE_OFF

			self._update_entity_state(
				self._get_pg_output_id(pg_output_number),
				pg_output_state,
			)

	def _get_lan_connection_device_number(self) -> int | None:
		if self._central_unit.model in ("JA-101K-LAN", "JA-106K-3G"):
			return 125

		if self._central_unit.model in ("JA-103K", "JA-103KRY", "JA-107K"):
			return 233

		return None

	def _get_gsm_device_number(self) -> int | None:
		if self._central_unit.model in ("JA-101K", "JA-101K-LAN", "JA-106K-3G"):
			return 127

		return None

	def _get_not_ignored_devices(self) -> List[int]:
		not_ignored_devices = []

		for number in range(1, self._config[CONF_NUMBER_OF_DEVICES] + 1):
			if not self._is_device_ignored(number):
				not_ignored_devices.append(number)

		return not_ignored_devices

	def _set_entity_initial_state(self, entity_id: str, initial_state: StateType):
		if entity_id in self.entities_states:
			# Loaded from stored data
			return

		self._update_entity_state(entity_id, initial_state, store_state=False)

	def _update_entity_state(self, entity_id: str, state: StateType, store_state: bool = True) -> None:
		if store_state is True:
			self._store_state(entity_id, state)

		if entity_id in self.entities_states and state == self.entities_states[entity_id]:
			return

		if entity_id in self.hass_entities:
			self.hass_entities[entity_id].update_state(state)
		else:
			self.entities_states[entity_id] = state

	def _log_incoming_packet(self, packet: bytes) -> None:
		if self._should_be_incoming_packet_logged(packet):
			self._log_debug_with_packet("Incoming", packet)

	def _log_outcoming_packet(self, packet: bytes) -> None:
		if self._should_be_outcoming_packet_logged(packet):
			self._log_debug_with_packet("Outcoming", packet)

	def _should_be_incoming_packet_logged(self, packet: bytes) -> bool:
		if not self._options.get(CONF_ENABLE_DEBUGGING, DEFAULT_CONF_ENABLE_DEBUGGING):
			return False

		if self._options.get(CONF_LOG_ALL_INCOMING_PACKETS, False):
			return True

		if (
			self._options.get(CONF_LOG_SECTIONS_PACKETS, False)
			and self._is_sections_states_packet(packet)
		):
			return True

		if (
			self._options.get(CONF_LOG_PG_OUTPUTS_PACKETS, False)
			and self._is_pg_outputs_states_packet(packet)
		):
			return True

		if (
			self._options.get(CONF_LOG_DEVICES_PACKETS, False)
			and self._is_device_packet(packet)
		):
			return True

		return False

	def _should_be_outcoming_packet_logged(self, packet: bytes) -> bool:
		if not self._options.get(CONF_ENABLE_DEBUGGING, DEFAULT_CONF_ENABLE_DEBUGGING):
			return False

		if self._options.get(CONF_LOG_ALL_OUTCOMING_PACKETS, False):
			return True

		if (
			self._options.get(CONF_LOG_SECTIONS_PACKETS, False)
			and self._is_section_modify_packet(packet)
		):
			return True

		if (
			self._options.get(CONF_LOG_PG_OUTPUTS_PACKETS, False)
			and self._is_pg_output_toggle_packet(packet)
		):
			return True

		if (
			self._options.get(CONF_LOG_DEVICES_PACKETS, False)
			and (
				self._is_device_get_status_packet(packet)
				or self._is_device_get_diagnostics_packet(packet)
				or self._is_devices_get_sections_packet(packet)
			)
		):
			return True

		return False

	def _store_state(self, entity_id: str, state: StateType) -> None:
		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			self._stored_data[serial_port] = {}

		if STORAGE_STATES_KEY not in self._stored_data[serial_port]:
			self._stored_data[serial_port][STORAGE_STATES_KEY] = {}

		if (
			entity_id in self._stored_data[serial_port][STORAGE_STATES_KEY]
			and self._stored_data[serial_port][STORAGE_STATES_KEY][entity_id] == state
		):
			return

		self._stored_data[serial_port][STORAGE_STATES_KEY][entity_id] = state
		self._store.async_delay_save(self._data_to_store)

	def _remove_stored_entity_state(self, entity_id: str) -> None:
		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			return

		if STORAGE_STATES_KEY not in self._stored_data[serial_port]:
			return

		if entity_id not in self._stored_data[serial_port][STORAGE_STATES_KEY]:
			return

		del self._stored_data[serial_port][STORAGE_STATES_KEY][entity_id]
		self._store.async_delay_save(self._data_to_store)

	def _store_devices_data(self) -> None:
		serial_port = self._config[CONF_SERIAL_PORT]

		if serial_port not in self._stored_data:
			self._stored_data[serial_port] = {}

		self._stored_data[serial_port][STORAGE_DEVICES_KEY] = self._devices_data
		self._store.async_delay_save(self._data_to_store)

	def _create_device_hass_device(self, device_number: int) -> JablotronHassDevice:
		device_id = self._get_device_id(device_number)
		device_type = self._get_device_type(device_number)

		battery_level: int | None = None
		if self.is_device_with_battery(device_number):
			battery_level = self._devices_data[device_id][DeviceData.BATTERY_LEVEL]

		return JablotronHassDevice(
			"device_{}".format(device_number),
			"{} (device {})".format(device_type.get_name(), device_number),
			battery_level,
		)

	def _add_battery_to_device(self, device_number: int, battery_level: int) -> None:
		device_id = self._get_device_id(device_number)

		self._devices_data[device_id][DeviceData.BATTERY_LEVEL] = battery_level

		self._store_devices_data()

		self._add_entity(
			self._device_hass_devices[device_id],
			EntityType.BATTERY_LEVEL,
			self._get_device_battery_level_sensor_id(device_number),
			self._get_device_battery_level_sensor_name(device_number),
			battery_level,
		)

		async_dispatcher_send(self._hass, self.signal_entities_added())

	def _add_entity(self, hass_device: JablotronHassDevice | None, entity_type: EntityType, entity_id: str, entity_name: str, initial_state: StateType = None) -> None:
		if entity_id in self.entities[entity_type]:
			return

		control = JablotronControl(
			self._central_unit,
			hass_device,
			entity_id,
			entity_name,
		)

		self.entities[entity_type][entity_id] = control

		self._set_entity_initial_state(entity_id, initial_state)

	async def _remove_entity(self, entity_type: EntityType, entity_id: str) -> None:
		if entity_id not in self.entities[entity_type]:
			return

		del self.entities[entity_type][entity_id]

		if entity_id in self.hass_entities:
			await self.hass_entities[entity_id].remove_from_hass()
			del self.hass_entities[entity_id]

		if entity_id in self.entities_states:
			del self.entities_states[entity_id]

		self._remove_stored_entity_state(entity_id)

	def _is_smoke_detector_in_section(self, section: int) -> bool:
		for device_id in self._devices_data:
			if self._devices_data[device_id][DeviceData.SECTION] == section:
				return True

		return False

	def _set_last_active_user_from_device_state_packet(self, packet: bytes, device_number: int) -> None:
		offset = 0
		if device_number not in (DeviceNumber.MOBILE_APPLICATION.value, DeviceNumber.USB.value):
			offset = 1

		self._last_active_user = int((self.bytes_to_int(packet[3:4]) - 104 - offset) / 4)
		LOGGER.debug("Active user: {}".format(self._last_active_user))

	@core.callback
	def _data_to_store(self) -> dict:
		return self._stored_data

	@staticmethod
	def _log_error_with_packet(description: str, packet: bytes) -> None:
		LOGGER.error("{}: {}".format(description, Jablotron.format_packet_to_string(packet)))

	@staticmethod
	def _log_debug_with_packet(description: str, packet: bytes) -> None:
		device_number = Jablotron._parse_device_number_from_packet(packet)

		if device_number is not None:
			description = "{} (device {})".format(description, device_number)

		LOGGER.debug("{}: {}".format(description, Jablotron.format_packet_to_string(packet)))

	@staticmethod
	def _is_sections_states_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_SECTIONS_STATES

	@staticmethod
	def _is_section_modify_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_UI_CONTROL and packet[2:3] == UI_CONTROL_MODIFY_SECTION

	@staticmethod
	def _is_login_error_packet(packet: bytes) -> bool:
		if (
			packet[:1] == PACKET_UI_CONTROL
			and packet[2:3] == b"\x1b"
			and packet[3:4] == b"\x03"
		):
			return True

		return False

	@staticmethod
	def _is_pg_outputs_states_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_PG_OUTPUTS_STATES

	@staticmethod
	def _is_pg_output_toggle_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_UI_CONTROL and packet[2:3] == UI_CONTROL_TOGGLE_PG_OUTPUT

	@staticmethod
	def _is_device_packet(packet: bytes) -> bool:
		return (
			Jablotron._is_devices_states_packet(packet)
			or Jablotron._is_devices_sections_packet(packet)
			or Jablotron._is_device_state_packet(packet)
			or Jablotron._is_device_info_packet(packet)
			or Jablotron._is_device_status_packet(packet)
		)

	@staticmethod
	def _is_devices_states_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_DEVICES_STATES

	@staticmethod
	def _is_devices_sections_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_DEVICES_SECTIONS

	@staticmethod
	def _is_devices_get_sections_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_GET_DEVICES_SECTIONS

	@staticmethod
	def _is_device_status_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_COMMAND and packet[2:3] == COMMAND_RESPONSE_DEVICE_STATUS

	@staticmethod
	def _is_device_get_status_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_COMMAND and packet[2:3] == COMMAND_GET_DEVICE_STATUS

	@staticmethod
	def _is_device_get_diagnostics_packet(packet: bytes) -> bool:
		return packet[:1] in (PACKET_DIAGNOSTICS, PACKET_DIAGNOSTICS_COMMAND)

	@staticmethod
	def _is_device_state_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_DEVICE_STATE

	@staticmethod
	def _is_device_info_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_DEVICE_INFO

	@staticmethod
	def _is_requested_device_info_packet(packet: bytes) -> bool:
		return Jablotron._is_device_info_packet(packet) and packet[3:4] == DEVICE_INFO_SUBPACKET_REQUESTED

	@staticmethod
	def _is_device_state_packet_for_state(packet_type: int) -> bool:
		return (
			not Jablotron._is_device_state_packet_for_fault(packet_type)
			and packet_type != DEVICE_PACKET_TYPE_HEARTBEAT
		)

	@staticmethod
	def _is_device_state_packet_for_fault(packet_type: int) -> bool:
		return packet_type in (
			DEVICE_PACKET_TYPE_POWER_SUPPLY_FAULT,
			DEVICE_PACKET_TYPE_SABOTAGE,
			DEVICE_PACKET_TYPE_FAULT,
		)

	@staticmethod
	def _convert_sections_states_packet_to_sections_states(packet: bytes) -> Dict[int, Dict[str, int | bool]]:
		section_states = {}

		for section in range(1, MAX_SECTIONS + 1):
			state_offset = section * 2
			state_packet = packet[state_offset:(state_offset + 2)]

			# Unused section
			if state_packet == b"\x07\x00":
				break

			section_states[section] = Jablotron._parse_jablotron_section_state(Jablotron._bytes_to_binary(state_packet[:1]) + Jablotron._bytes_to_binary(state_packet[1:]))

		return section_states

	@staticmethod
	def _parse_device_number_from_device_status_packet(packet: bytes) -> int:
		return Jablotron.bytes_to_int(packet[3:4])

	@staticmethod
	def _parse_device_connection_type_from_device_status_packet(packet: bytes) -> DeviceConnection:
		packet_length = Jablotron.bytes_to_int(packet[1:2])
		return DeviceConnection.WIRELESS if packet_length == 9 else DeviceConnection.WIRED

	@staticmethod
	def _parse_device_signal_strength_from_device_status_packet(packet: bytes) -> int | None:
		number = Jablotron.bytes_to_int(packet[9:10])
		return (number & 0x1f) * SIGNAL_STRENGTH_STEP

	@staticmethod
	def _parse_device_battery_level_from_device_status_packet(packet: bytes) -> int | None:
		try:
			return Jablotron._parse_device_battery_level_packet(packet[10:11])
		except InvalidBatteryLevel:
			Jablotron._log_debug_with_packet(
				"Unknown battery level packet of device {}".format(Jablotron._parse_device_number_from_device_status_packet(packet)),
				packet,
			)

			return None

	@staticmethod
	def _parse_device_number_from_device_state_packet(packet: bytes) -> int:
		return int(Jablotron.bytes_to_int(packet[4:6]) / 64)

	@staticmethod
	def _parse_device_number_from_device_info_packet(packet: bytes) -> int:
		return Jablotron.bytes_to_int(packet[2:3])

	@staticmethod
	def _parse_device_number_from_packet(packet: bytes) -> int | None:
		if Jablotron._is_device_status_packet(packet):
			return Jablotron._parse_device_number_from_device_status_packet(packet)

		if Jablotron._is_device_info_packet(packet):
			return Jablotron._parse_device_number_from_device_info_packet(packet)

		if Jablotron._is_device_state_packet(packet):
			return Jablotron._parse_device_number_from_device_state_packet(packet)

		if Jablotron._is_device_get_status_packet(packet):
			return Jablotron.bytes_to_int(packet[3:4])

		if Jablotron._is_device_get_diagnostics_packet(packet):
			return Jablotron.bytes_to_int(packet[2:3])

		return None

	@staticmethod
	def _parse_device_info_packets_from_device_info_packet(packet: bytes) -> List[bytes]:
		raw_info_packet = packet[7:]

		info_packets = []

		info_type_length = {
			DEVICE_INFO_TYPE_POWER: 4,
			DEVICE_INFO_TYPE_SMOKE: 4,
			DEVICE_INFO_TYPE_PULSE: 14,
			DEVICE_INFO_TYPE_INPUT_VALUE: 5,
			DEVICE_INFO_TYPE_INPUT_EXTENDED: 2,
		}

		start = 0
		while start < len(raw_info_packet):
			info_type = raw_info_packet[start:(start + 1)]

			if info_type == b"\x00":
				break

			if info_type not in DEVICE_INFO_KNOWN_TYPES:
				Jablotron._log_error_with_packet(
					"Unknown device info type {}".format(Jablotron.format_packet_to_string(info_type)),
					packet,
				)
				break

			end = start + info_type_length[info_type] + 1

			info_packets.append(raw_info_packet[start:end])

			start = end

		return info_packets

	@staticmethod
	def _parse_device_battery_level_from_device_info_packet(packet: bytes) -> int | None:
		packet_binary = Jablotron._bytes_to_binary(packet[5:6])

		try:
			return Jablotron._parse_device_battery_level_packet(Jablotron.int_to_bytes(Jablotron.binary_to_int(packet_binary[4:])))
		except InvalidBatteryLevel:
			Jablotron._log_debug_with_packet(
				"Unknown battery level packet of device {}".format(Jablotron._parse_device_number_from_device_info_packet(packet)),
				packet,
			)

			return None

	@staticmethod
	def _parse_device_battery_level_packet(battery_level_packet: bytes) -> int | None:
		if battery_level_packet in BATTERY_LEVELS_TO_IGNORE:
			return None

		battery_level = Jablotron.bytes_to_int(battery_level_packet)

		if battery_level > 10:
			raise InvalidBatteryLevel

		return battery_level * BATTERY_LEVEL_STEP

	@staticmethod
	def _convert_jablotron_device_state_to_state(packet: bytes, device_number: int) -> str | None:
		state = Jablotron.bytes_to_int(packet[3:4])

		if device_number <= 37:
			high_device_number_offset = 0
		elif device_number <= 101:
			high_device_number_offset = -64
		elif device_number <= 165:
			high_device_number_offset = -128
		else:
			high_device_number_offset = -256

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
	def _bytes_to_binary(packet: bytes) -> str:
		dec = Jablotron.bytes_to_int(packet)
		bin_dec = bin(dec)
		binary_string = bin_dec[2:]
		return binary_string.zfill(len(packet) * 8)

	@staticmethod
	def _bytes_to_reverse_binary(packet: bytes) -> str:
		binary_string = Jablotron._bytes_to_binary(packet)
		return binary_string[::-1]

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
	def _get_section_fire_sensor_id(section: int) -> str:
		return "section_fire_sensor_{}".format(section)

	@staticmethod
	def _get_section_fire_sensor_name(section: int) -> str:
		return "Fire in section {}".format(section)

	@staticmethod
	def _get_device_state_sensor_id(device_number: int) -> str:
		return "device_sensor_{}".format(device_number)

	def _get_device_sensor_name(self, device_number: int) -> str:
		return "{} (device {})".format(self._get_device_name(device_number), device_number)

	@staticmethod
	def _get_device_problem_sensor_id(device_number: int) -> str:
		return "device_problem_sensor_{}".format(device_number)

	def _get_device_problem_sensor_name(self, device_number: int) -> str:
		return "Problem of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_signal_strength_sensor_id(device_number: int) -> str:
		return "device_signal_strength_sensor_{}".format(device_number)

	def _get_device_signal_strength_sensor_name(self, device_number: int) -> str:
		return "Signal strength of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_battery_level_sensor_id(device_number: int) -> str:
		return "device_battery_level_sensor_{}".format(device_number)

	def _get_device_battery_level_sensor_name(self, device_number: int) -> str:
		return "Battery level of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_temperature_sensor_id(device_number: int) -> str:
		return "device_temperature_sensor_{}".format(device_number)

	def _get_device_temperature_sensor_name(self, device_number: int) -> str:
		return "Temperature of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_battery_standby_voltage_sensor_id(device_number: int) -> str:
		return "battery_standby_voltage_{}".format(device_number)

	def _get_device_battery_standby_voltage_sensor_name(self, device_number: int) -> str:
		return "Battery standby voltage of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_battery_load_voltage_sensor_id(device_number: int) -> str:
		return "battery_load_voltage_{}".format(device_number)

	def _get_device_battery_load_voltage_sensor_name(self, device_number: int) -> str:
		return "Battery load voltage of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_bus_voltage_sensor_id(device_number: int) -> str:
		return "bus_voltage_{}".format(device_number)

	def _get_device_bus_voltage_sensor_name(self, device_number: int) -> str:
		return "BUS voltage of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_bus_devices_loss_sensor_id(device_number: int) -> str:
		return "bus_devices_loss_{}".format(device_number)

	def _get_device_bus_devices_loss_sensor_name(self, device_number: int) -> str:
		return "BUS devices loss of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_device_pulse_sensor_id(device_number: int) -> str:
		return "pulses_{}".format(device_number)

	def _get_device_pulse_sensor_name(self, device_number: int) -> str:
		return "Pulses of {} (device {})".format(self._get_device_name(device_number).lower(), device_number)

	@staticmethod
	def _get_lan_connection_id() -> str:
		return "lan"

	@staticmethod
	def _get_lan_connection_name() -> str:
		return "LAN connection"

	@staticmethod
	def _get_lan_connection_ip_id() -> str:
		return "lan_ip"

	@staticmethod
	def _get_lan_connection_ip_name() -> str:
		return "LAN IP"

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
	def _convert_jablotron_section_state_to_alarm_state(state: Dict[str, int | bool]) -> StateType:
		if state["state"] in (SECTION_PRIMARY_STATE_SERVICE, SECTION_PRIMARY_STATE_BLOCKED):
			return None

		if state["triggered"] is True:
			return STATE_ALARM_TRIGGERED

		if state["pending"] is True:
			return STATE_ALARM_PENDING

		if state["arming"] is True:
			return STATE_ALARM_ARMING

		if state["state"] == SECTION_PRIMARY_STATE_ARMED_FULL:
			return STATE_ALARM_ARMED_AWAY

		if state["state"] == SECTION_PRIMARY_STATE_ARMED_PARTIALLY:
			return STATE_ALARM_ARMED_NIGHT

		return STATE_ALARM_DISARMED

	@staticmethod
	def _convert_jablotron_section_state_to_problem_sensor_state(state: Dict[str, int | bool]) -> StateType:
		return STATE_ON if state["problem"] or state["sabotage"] else STATE_OFF

	@staticmethod
	def _convert_jablotron_section_state_to_fire_sensor_state(state: Dict[str, int | bool]) -> StateType:
		return STATE_ON if state["fire"] else STATE_OFF

	@staticmethod
	def _parse_jablotron_section_state(section_binary: str) -> Dict[str, int | bool]:
		state = Jablotron.binary_to_int(section_binary[5:8])

		return {
			"state": state,
			"pending": section_binary[1:2] == "1",
			"arming": section_binary[0:1] == "1",
			"triggered": section_binary[3:4] == "1" or section_binary[4:5] == "1",
			"problem": section_binary[2:3] == "1",
			"sabotage": section_binary[11:12] == "1",
			"fire": section_binary[14:15] == "1",
			"alert": section_binary[13:14] == "1",
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
	def bytes_to_float(packet: bytes) -> float:
		return round(Jablotron.bytes_to_int(packet) / 10, 1)

	@staticmethod
	def binary_to_int(binary: str) -> int:
		return int(binary, 2)

	@staticmethod
	def int_to_bytes(number: int) -> bytes:
		return int.to_bytes(number, 1, byteorder=sys.byteorder)

	@staticmethod
	def create_packet(packet_type: bytes, data: bytes) -> bytes:
		return packet_type + Jablotron.int_to_bytes(len(data)) + data

	@staticmethod
	def create_packet_get_system_info(info_type: int) -> bytes:
		return Jablotron.create_packet(PACKET_GET_SYSTEM_INFO, Jablotron.int_to_bytes(info_type))

	@staticmethod
	def create_packet_command(command_type: bytes, data: bytes | None = b"") -> bytes:
		return Jablotron.create_packet(PACKET_COMMAND, command_type + data)

	@staticmethod
	def create_packet_ui_control(control_type: bytes, data: bytes | None = b"") -> bytes:
		return Jablotron.create_packet(PACKET_UI_CONTROL, control_type + data)

	@staticmethod
	def create_packet_enable_device_states() -> bytes:
		return Jablotron.create_packet_command(COMMAND_ENABLE_DEVICE_STATE_PACKETS, Jablotron.int_to_bytes(TIMEOUT_FOR_DEVICE_STATE_PACKETS))

	@staticmethod
	def create_packet_device_info(device_number: int) -> bytes:
		return Jablotron.create_packet_command(COMMAND_GET_DEVICE_STATUS, Jablotron.int_to_bytes(device_number))

	@staticmethod
	def _create_packet_device_diagnostics_start(device_number: int) -> bytes:
		return Jablotron.create_packet(PACKET_DIAGNOSTICS, Jablotron.int_to_bytes(device_number) + DIAGNOSTICS_ON)

	@staticmethod
	def _create_packet_device_diagnostics_force_info(device_number: int) -> bytes:
		return Jablotron.create_packet(PACKET_DIAGNOSTICS_COMMAND, Jablotron.int_to_bytes(device_number) + DIAGNOSTICS_COMMAND_GET_INFO + b"\x00")

	@staticmethod
	def _create_packet_device_diagnostics_end(device_number: int) -> bytes:
		return Jablotron.create_packet(PACKET_DIAGNOSTICS, Jablotron.int_to_bytes(device_number) + DIAGNOSTICS_OFF)

	@staticmethod
	def create_packet_authorisation_code(code: str) -> bytes:
		magic_offset = 48

		if code.find("*") != -1:
			code_packet = b""

			code = code.rjust(8, "0")

			for j in range(0, len(code)):
				letter = code[j:(j + 1)]

				if letter == "*":
					continue

				code_number = magic_offset + int(letter)
				code_packet += Jablotron.int_to_bytes(code_number)

		else:
			code_packet = b"\x39\x39\x39"

			for i in range(0, 4):
				j = i + 4

				first_number = code[j:(j + 1)]
				second_number = code[i:(i + 1)]

				if first_number == "":
					code_number = magic_offset + int(second_number)
				else:
					code_number = int(f"{first_number}{second_number}", 16)

				code_packet += Jablotron.int_to_bytes(code_number)

		return Jablotron.create_packet_ui_control(UI_CONTROL_AUTHORISATION_CODE, code_packet)

	@staticmethod
	def create_packets_keepalive(code: str) -> List[bytes]:
		return [
			Jablotron.create_packet_authorisation_code(code),
			Jablotron.create_packet_enable_device_states(),
		]


class JablotronEntity(Entity):

	_attr_should_poll = False

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronControl,
	) -> None:
		self._jablotron: Jablotron = jablotron
		self._control: JablotronControl = control

		self._attr_unique_id = "{}.{}.{}".format(DOMAIN, self._control.central_unit.serial_port, self._control.id)

		self._attr_name = self._control.name

		if self._control.hass_device is None:
			self._attr_device_info = {
				"manufacturer": "Jablotron",
				"identifiers": {(DOMAIN, self._control.central_unit.serial_port)},
			}
		else:
			self._attr_device_info = {
				"manufacturer": "Jablotron",
				"identifiers": {(DOMAIN, self._control.hass_device.id)},
				"name": self._control.hass_device.name,
				"via_device": (DOMAIN, self._control.central_unit.serial_port),
			}

		self._update_attributes()

	def _update_attributes(self) -> None:
		if self._control.hass_device is not None and self._control.hass_device.battery_level is not None:
			self._attr_extra_state_attributes = {
				ATTR_BATTERY_LEVEL: self._control.hass_device.battery_level,
			}

	@property
	def available(self) -> bool:
		if self._jablotron.in_service_mode is True:
			return False

		if self._get_state() is None:
			return False

		return self._jablotron.last_update_success

	async def async_added_to_hass(self) -> None:
		self._jablotron.substribe_hass_entity_for_updates(self._control.id, self)

	async def remove_from_hass(self) -> None:
		if self.registry_entry:
			er.async_get(self.hass).async_remove(self.entity_id)
		else:
			await self.async_remove(force_remove=True)

	def refresh_state(self) -> None:
		self._update_attributes()
		self.async_write_ha_state()

	def update_state(self, state: StateType) -> None:
		self._jablotron.entities_states[self._control.id] = state
		self.refresh_state()

	def _get_state(self) -> StateType:
		return self._jablotron.entities_states[self._control.id]
