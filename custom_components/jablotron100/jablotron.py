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
	STATE_ALARM_ARMED_HOME,
	STATE_ALARM_ARMED_NIGHT,
	STATE_ALARM_ARMING,
	STATE_ALARM_PENDING,
	STATE_ALARM_TRIGGERED,
	STATE_OFF,
	STATE_ON,
)
from homeassistant.helpers import storage
from homeassistant.helpers.dispatcher import async_dispatcher_send
from homeassistant.helpers.entity import DeviceInfo, Entity
from homeassistant.helpers.event import async_call_later
from homeassistant.helpers.typing import StateType
from homeassistant.helpers import entity_registry as er
import math
import os
import sys
import threading
import time
from .const import (
	AUTODETECT_SERIAL_PORT,
	BATTERY_LEVEL_NO_BATTERY,
	BATTERY_LEVEL_NO_CHANGE_FROM_PREVIOUS_STATE,
	BATTERY_LEVELS_TO_IGNORE,
	BATTERY_LEVEL_STEP,
	CentralUnitData,
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
	CONF_PARTIALLY_ARMING_MODE,
	CONF_REQUIRE_CODE_TO_ARM,
	CONF_REQUIRE_CODE_TO_DISARM,
	CONF_SERIAL_PORT,
	CONF_UNIQUE_ID,
	DEFAULT_CONF_ENABLE_DEBUGGING,
	DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
	DEVICE_INFO_KNOWN_SUBPACKETS,
	DEVICE_INFO_SUBPACKET_WIRELESS,
	DEVICE_INFO_SUBPACKET_REQUESTED,
	DEVICE_INFO_UNKNOWN_SUBPACKETS,
	DIAGNOSTICS_COMMAND_GET_INFO,
	DIAGNOSTICS_OFF,
	DIAGNOSTICS_ON,
	DOMAIN,
	DeviceConnection,
	DeviceData,
	DeviceFault,
	DeviceInfoType,
	DeviceNumber,
	DeviceType,
	EVENT_WRONG_CODE,
	EMPTY_PACKET,
	EntityType,
	EventLoginType,
	HIDRAW_PATH,
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
	PartiallyArmingMode,
	PG_OUTPUT_TURN_OFF,
	PG_OUTPUT_TURN_ON,
	SIGNAL_STRENGTH_STEP,
	STREAM_MAX_WORKERS,
	STREAM_PACKET_SIZE,
	STREAM_TIMEOUT,
	SectionPrimaryState,
	SystemInfo,
	TIMEOUT_FOR_DEVICE_STATE_PACKETS,
	UI_CONTROL_AUTHORISATION_CODE,
	UI_CONTROL_AUTHORISATION_END,
	UI_CONTROL_MODIFY_SECTION,
	UI_CONTROL_TOGGLE_PG_OUTPUT,
)
from typing import Any, Dict, Final, List
from .errors import (
	ServiceUnavailable,
	ShouldNotHappen,
	InvalidBatteryLevel,
)

STORAGE_VERSION: Final = 2
STORAGE_CENTRAL_UNIT_KEY: Final = "central_unit"
STORAGE_DEVICES_KEY: Final = "devices"
STORAGE_STATES_KEY: Final = "states"

DEVICE_TYPE_TO_ENTITY_TYPE: Final = {
	DeviceType.MOTION_DETECTOR: EntityType.DEVICE_STATE_MOTION,
	DeviceType.WINDOW_OPENING_DETECTOR: EntityType.DEVICE_STATE_WINDOW,
	DeviceType.DOOR_OPENING_DETECTOR: EntityType.DEVICE_STATE_DOOR,
	DeviceType.GARAGE_DOOR_OPENING_DETECTOR: EntityType.DEVICE_STATE_GARAGE_DOOR,
	DeviceType.GLASS_BREAK_DETECTOR: EntityType.DEVICE_STATE_GLASS,
	DeviceType.FLOOD_DETECTOR: EntityType.DEVICE_STATE_MOISTURE,
	DeviceType.GAS_DETECTOR: EntityType.DEVICE_STATE_GAS,
	DeviceType.SMOKE_DETECTOR: EntityType.DEVICE_STATE_SMOKE,
	DeviceType.LOCK: EntityType.DEVICE_STATE_LOCK,
	DeviceType.TAMPER: EntityType.DEVICE_STATE_TAMPER,
	DeviceType.THERMOSTAT: EntityType.DEVICE_STATE_THERMOSTAT,
	DeviceType.THERMOMETER: EntityType.DEVICE_STATE_THERMOMETER,
	DeviceType.SIREN_INDOOR: EntityType.DEVICE_STATE_INDOOR_SIREN_BUTTON,
	DeviceType.BUTTON: EntityType.DEVICE_STATE_BUTTON,
	DeviceType.KEY_FOB: EntityType.DEVICE_STATE_BUTTON,
	DeviceType.VALVE: EntityType.DEVICE_STATE_VALVE,
	DeviceType.CUSTOM: EntityType.DEVICE_STATE_CUSTOM,
}

class ParsedDeviceInfoPacket:

	def __init__(self, packet_type: DeviceInfoType, packet: bytes) -> None:
		self.type: DeviceInfoType = packet_type
		self.packet: bytes = packet

class JablotronSectionState:

	def __init__(self, state: SectionPrimaryState, pending: bool, arming: bool, triggered: bool, problem: bool, sabotage: bool, fire: bool) -> None:
		self.state: SectionPrimaryState = state
		self.arming: bool = arming
		self.pending: bool = pending
		self.triggered: bool = triggered
		self.problem: bool = problem
		self.sabotage: bool = sabotage
		self.fire: bool = fire


class JablotronCentralUnit:

	def __init__(self, unique_id: str, model: str, hardware_version: str, firmware_version: str) -> None:
		self.unique_id: str = unique_id
		self.model: str = model
		self.hardware_version: str = hardware_version
		self.firmware_version: str = firmware_version


class JablotronHassDevice:

	def __init__(self, device_id: str, device_name: str, battery_level: int | None = None) -> None:
		self.id: str = device_id
		self.name: str = device_name
		self.battery_level: int | None = battery_level


class JablotronControl:

	def __init__(self, central_unit: JablotronCentralUnit, hass_device: JablotronHassDevice | None, control_id: str, control_name: str | None = None) -> None:
		self.central_unit: JablotronCentralUnit = central_unit
		self.hass_device: JablotronHassDevice | None = hass_device
		self.id: str = control_id
		self.name: str | None = control_name


class JablotronAlarmControlPanel(JablotronControl):

	def __init__(self, central_unit: JablotronCentralUnit, hass_device: JablotronHassDevice, panel_id: str, section: int) -> None:
		self.section: int = section

		super().__init__(central_unit, hass_device, panel_id)


class JablotronProgrammableOutput(JablotronControl):

	def __init__(self, central_unit: JablotronCentralUnit, pg_output_id: str, pg_output_name: str, pg_output_number: int) -> None:
		self.pg_output_number: int = pg_output_number

		super().__init__(central_unit, None, pg_output_id, pg_output_name)


class JablotronBatteryState:

	def __init__(self, ok: bool, level: int) -> None:
		self.ok: bool = ok
		self.level: int = level


class Jablotron:

	def __init__(self, hass: core.HomeAssistant, config_entry_id: str, config: Dict[str, Any], options: Dict[str, Any]) -> None:
		self._hass: core.HomeAssistant = hass
		self._config_entry_id: str = config_entry_id
		self._config: Dict[str, Any] = config
		self._options: Dict[str, Any] = options
		self._main_thread = threading.current_thread()

		self._central_unit: JablotronCentralUnit | None = None
		self._device_hass_devices: Dict[str, JablotronHassDevice] = {}

		self.entities: Dict[EntityType, Dict[str, JablotronControl]] = {}
		for entity_type in EntityType.__members__.values():
			self.entities[entity_type] = {}

		self.entities_states: Dict[str, StateType] = {}
		self.hass_entities: Dict[str, JablotronEntity] = {}

		self._serial_port: str | None = None

		self._stream_thread_pool_executor: ThreadPoolExecutor | None = None
		self._stream_stop_event: threading.Event = threading.Event()
		self._stream_data_updating_event: threading.Event = threading.Event()
		self._stream_diagnostics_event: threading.Event = threading.Event()

		self._store: storage.Store = storage.Store(hass, STORAGE_VERSION, DOMAIN)
		self._stored_data: dict | None = None

		self._central_unit_data: Dict[CentralUnitData, Any] = {}
		self._devices_data: Dict[str, Dict[DeviceData, Any]] = {}

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

	def partially_arming_mode(self) -> PartiallyArmingMode:
		return PartiallyArmingMode(self._options.get(CONF_PARTIALLY_ARMING_MODE, PartiallyArmingMode.NIGHT_MODE.value))

	def code_contains_asterisk(self) -> bool:
		return self._config[CONF_PASSWORD].find("*") != -1

	def last_active_user(self) -> int | None:
		return self._last_active_user

	async def initialize(self) -> None:
		def shutdown_event(_):
			self.shutdown()

		self._hass.bus.async_listen(EVENT_HOMEASSISTANT_STOP, shutdown_event)

		await self._load_stored_data()

		if self._config[CONF_SERIAL_PORT] == AUTODETECT_SERIAL_PORT:
			self._serial_port = self.detect_serial_port()
			if self._serial_port is None:
				raise ServiceUnavailable("No serial port found")
		else:
			self._serial_port = self._config[CONF_SERIAL_PORT]

		self._detect_central_unit()
		await self._detect_and_create_devices_and_sections_and_pg_outputs()
		self._create_central_unit_sensors()

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

		unique_id = self._get_unique_id()
		del self._stored_data[unique_id]
		self._store_data_to_store_threadsafe()

	def shutdown(self) -> None:
		self._stream_stop_event.set()

		if self._stream_thread_pool_executor is not None:
			self._stream_thread_pool_executor.shutdown(wait=False, cancel_futures=True)

	def subscribe_hass_entity_for_updates(self, control_id: str, hass_entity: JablotronEntity) -> None:
		self.hass_entities[control_id] = hass_entity

	def modify_alarm_control_panel_section_state(self, section: int, state: StateType, code: str | None) -> None:
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
			STATE_ALARM_ARMED_HOME: 175,
			STATE_ALARM_ARMED_NIGHT: 175,
		}

		# Reset
		self._successful_login = True

		def after_modify_callback(_) -> None:
			self._send_packet(self.create_packet_command(COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES))

		def after_login_callback(_) -> None:
			if self._successful_login is True:
				modify_packet = self.int_to_bytes(int_packets[state] + section)
				self._send_packet(self.create_packet_ui_control(UI_CONTROL_MODIFY_SECTION, modify_packet))

			if code != self._config[CONF_PASSWORD]:
				logout_packets = [self.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END)]
				logout_packets.extend(self.create_packets_keepalive(self._config[CONF_PASSWORD]))

				self._send_packets(logout_packets)

			async_call_later(self._hass, 1.0, after_modify_callback)

		if code != self._config[CONF_PASSWORD]:
			login_packets = [
				self.create_packet_ui_control(UI_CONTROL_AUTHORISATION_END),
				self.create_packet_authorisation_code(code),
			]

			self._send_packets(login_packets)

			async_call_later(self._hass, 1.0, after_login_callback)
		else:
			after_login_callback(None)

	def toggle_pg_output(self, pg_output_number: int, state: str) -> None:
		pg_output_number_packet = self.int_to_bytes(pg_output_number - 1)
		state_packet = PG_OUTPUT_TURN_ON if state == STATE_ON else PG_OUTPUT_TURN_OFF

		packet = self.create_packet_ui_control(UI_CONTROL_TOGGLE_PG_OUTPUT, pg_output_number_packet + state_packet)

		self._send_packet(packet)

	def reset_problem_sensor(self, control: JablotronControl) -> None:
		self._update_entity_state(control.id, STATE_OFF)

	def _update_all_hass_entities(self) -> None:
		for hass_entity in self.hass_entities.values():
			hass_entity.refresh_state()

	async def _load_stored_data(self) -> None:
		try:
			self._stored_data = await self._store.async_load()
		except NotImplementedError:
			# Version upgrade - no migration implemented
			pass

		if self._stored_data is None:
			self._stored_data = {}

		unique_id = self._get_unique_id()

		if unique_id not in self._stored_data:
			return

		if STORAGE_CENTRAL_UNIT_KEY in self._stored_data[unique_id]:
			self._central_unit_data = copy.deepcopy(self._stored_data[unique_id][STORAGE_CENTRAL_UNIT_KEY])

		if STORAGE_DEVICES_KEY in self._stored_data[unique_id]:
			self._devices_data = copy.deepcopy(self._stored_data[unique_id][STORAGE_DEVICES_KEY])

		if STORAGE_STATES_KEY in self._stored_data[unique_id]:
			self.entities_states = copy.deepcopy(self._stored_data[unique_id][STORAGE_STATES_KEY])

	def _get_unique_id(self) -> str:
		return self._config[CONF_UNIQUE_ID] if CONF_UNIQUE_ID in self._config else self._config[CONF_SERIAL_PORT]

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
							info_type = SystemInfo(self.bytes_to_int(packet[2:3]))
							if info_type == SystemInfo.MODEL:
								model = self.decode_system_info_packet(packet)
							elif info_type == SystemInfo.HARDWARE_VERSION:
								hardware_version = self.decode_system_info_packet(packet)
							elif info_type == SystemInfo.FIRMWARE_VERSION:
								firmware_version = self.decode_system_info_packet(packet)
						except (KeyError, TypeError):
							# Unknown/Ignored info type packet
							pass
						except UnicodeDecodeError:
							# Try again
							pass

					if model is not None and hardware_version is not None and firmware_version is not None:
						break
			finally:
				stream.close()

			if model is None or hardware_version is None or firmware_version is None:
				return None

			return JablotronCentralUnit(self._get_unique_id(), model, hardware_version, firmware_version)

		def writer_thread() -> None:
			while not stop_event.is_set():
				self._send_packets([
					self.create_packet_get_system_info(SystemInfo.MODEL),
					self.create_packet_get_system_info(SystemInfo.HARDWARE_VERSION),
					self.create_packet_get_system_info(SystemInfo.FIRMWARE_VERSION),
				])
				time.sleep(1)

		try:
			reader = thread_pool_executor.submit(reader_thread)
			thread_pool_executor.submit(writer_thread)

			self._central_unit = reader.result(STREAM_TIMEOUT)

		except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
			LOGGER.exception("Service unavailable: %s", ex)
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
			LOGGER.exception("Service unavailable: %s", ex)
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

	def _create_section(self, section: int, section_state: JablotronSectionState) -> bool:
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
				section,
			)
			self._set_entity_initial_state(section_alarm_id, self._convert_jablotron_section_state_to_alarm_state(section_state, self.partially_arming_mode()))

		self._add_entity(
			section_hass_device,
			EntityType.PROBLEM,
			section_problem_sensor_id,
			self._convert_jablotron_section_state_to_problem_sensor_state(section_state),
		)

		if section_has_smoke_detector:
			self._add_entity(
				section_hass_device,
				EntityType.FIRE,
				section_fire_sensor_id,
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
			LOGGER.exception("Service unavailable: %s", ex)
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
					DeviceData.BATTERY: False,
					DeviceData.BATTERY_LEVEL: None,
					DeviceData.SECTION: None,
				}

				if device_connection == DeviceConnection.WIRELESS:
					signal_strength = self._parse_device_signal_strength_from_device_status_packet(packet)
					self._devices_data[device_id][DeviceData.SIGNAL_STRENGTH] = signal_strength

					battery_state = self._parse_device_battery_level_from_device_status_packet(packet)
					if battery_state is not None:
						self._devices_data[device_id][DeviceData.BATTERY] = True
						self._devices_data[device_id][DeviceData.BATTERY_LEVEL] = battery_state.level
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
				STATE_OFF,
			)

			# State sensor
			if self._is_device_with_state(device_number):
				self._add_entity(
					hass_device,
					self._get_device_state_entity_type(device_type),
					self._get_device_state_sensor_id(device_number),
					STATE_OFF,
				)

			# Signal strength sensor
			device_signal_strength_sensor_id = self._get_device_signal_strength_sensor_id(device_number)
			if self.is_wireless_device(device_number):
				self._add_entity(
					hass_device,
					EntityType.SIGNAL_STRENGTH,
					device_signal_strength_sensor_id,
					self._devices_data[device_id][DeviceData.SIGNAL_STRENGTH],
				)
			else:
				await self._remove_entity(EntityType.SIGNAL_STRENGTH, device_signal_strength_sensor_id)

			# Battery sensors
			device_battery_problem_sensor_id = self._get_device_battery_problem_sensor_id(device_number)
			device_battery_level_sensor_id = self._get_device_battery_level_sensor_id(device_number)
			if self.is_device_with_battery(device_number):
				self._add_battery_entities(device_number, JablotronBatteryState(True, self._devices_data[device_id][DeviceData.BATTERY_LEVEL]))
			else:
				await self._remove_entity(EntityType.BATTERY_PROBLEM, device_battery_problem_sensor_id)
				await self._remove_entity(EntityType.BATTERY_LEVEL, device_battery_level_sensor_id)

			# Battery voltage sensors
			device_battery_standby_voltage_sensor_id = self._get_device_battery_standby_voltage_sensor_id(device_number)
			device_battery_load_voltage_sensor_id = self._get_device_battery_load_voltage_sensor_id(device_number)
			if (
				self.is_device_with_battery(device_number)
				and device_type in (DeviceType.SIREN_OUTDOOR, DeviceType.SIREN_INDOOR)
			):
				self._add_battery_voltage_entities(device_number)
			else:
				await self._remove_entity(EntityType.BATTERY_STANDBY_VOLTAGE, device_battery_standby_voltage_sensor_id)
				await self._remove_entity(EntityType.BATTERY_LOAD_VOLTAGE, device_battery_load_voltage_sensor_id)

			# Temperature sensor
			device_temperature_sensor_id = self._get_device_temperature_sensor_id(device_number)
			if device_type in (DeviceType.THERMOMETER, DeviceType.THERMOSTAT, DeviceType.SMOKE_DETECTOR):
				self._add_entity(
					hass_device,
					EntityType.TEMPERATURE,
					device_temperature_sensor_id,
				)
			else:
				await self._remove_entity(EntityType.TEMPERATURE, device_temperature_sensor_id)

			# Pulses sensor
			if device_type == DeviceType.ELECTRICITY_METER_WITH_PULSE_OUTPUT:
				self._add_pulse_to_electricity_meter(device_number)
			else:
				# We can add only two sensors currently
				await self._remove_entity(EntityType.PULSES, self._get_device_pulse_sensor_id(device_number))
				await self._remove_entity(EntityType.PULSES, self._get_device_pulse_sensor_id(device_number, 1))

	def _create_central_unit_sensors(self) -> None:
		if CentralUnitData.BATTERY not in self._central_unit_data:
			self._central_unit_data[CentralUnitData.BATTERY] = False
			self._central_unit_data[CentralUnitData.BATTERY_LEVEL] = None
		if CentralUnitData.BUSES not in self._central_unit_data:
			self._central_unit_data[CentralUnitData.BUSES] = [1]

		self._add_entity(
			None,
			EntityType.EVENT_LOGIN,
			"login",
			STATE_ON, # Fake state so the entity is available
		)

		self._add_entity(
			None,
			EntityType.POWER_SUPPLY,
			self._get_device_power_supply_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			STATE_OFF,
		)

		if self._central_unit_data[CentralUnitData.BATTERY]:
			self._add_entity(
				None,
				EntityType.BATTERY_PROBLEM,
				self._get_device_battery_problem_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			)

			self._add_entity(
				None,
				EntityType.BATTERY_LEVEL,
				self._get_device_battery_level_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			)

			self._add_entity(
				None,
				EntityType.BATTERY_STANDBY_VOLTAGE,
				self._get_device_battery_standby_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			)

			self._add_entity(
				None,
				EntityType.BATTERY_LOAD_VOLTAGE,
				self._get_device_battery_load_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			)

		for bus_number in self._central_unit_data[CentralUnitData.BUSES]:
			self._add_central_unit_bus_entities(bus_number)

		if self._get_central_unit_lan_connection_device_number() is not None:
			if CentralUnitData.LAN_IP not in self._central_unit_data:
				self._central_unit_data[CentralUnitData.LAN_IP] = False

			self._add_entity(
				None,
				EntityType.LAN_CONNECTION,
				self._get_lan_connection_id(),
				STATE_ON,
			)

			if self._central_unit_data[CentralUnitData.LAN_IP]:
				self._add_entity(
					None,
					EntityType.LAN_IP,
					self._get_lan_connection_ip_id(),
				)

		if self._get_central_unit_gsm_device_number() is not None:
			self._add_entity(
				None,
				EntityType.GSM_SIGNAL,
				self._get_gsm_signal_sensor_id(),
				STATE_ON,
			)

			self._add_entity(
				None,
				EntityType.GSM_SIGNAL_STRENGTH,
				self._get_gsm_signal_strength_sensor_id(),
				100,
			)

	def _force_devices_status_update(self) -> None:
		packets = []

		if self._is_central_unit_101_or_similar():
			power_supply_device_number = self._get_central_unit_power_supply_device_number()
			if power_supply_device_number is not None:
				packets.append(self.create_packet_device_info(power_supply_device_number))

			gsm_device_number = self._get_central_unit_gsm_device_number()
			if gsm_device_number is not None:
				packets.append(self.create_packet_device_info(gsm_device_number))

			lan_connection_device_number = self._get_central_unit_lan_connection_device_number()
			if lan_connection_device_number is not None:
				packets.append(self.create_packet_device_info(lan_connection_device_number))

		for device_number in self._get_not_ignored_devices():
			if self.is_wireless_device(device_number):
				packets.append(self.create_packet_device_info(device_number))

		if len(packets) > 0:
			self._send_packets(packets)

	def _force_devices_info_update(self) -> None:
		devices_to_update = []

		for device_number in self._get_not_ignored_devices():
			device_type = self._get_device_type(device_number)

			if device_type in (DeviceType.THERMOMETER, DeviceType.THERMOSTAT, DeviceType.SMOKE_DETECTOR, DeviceType.SIREN_OUTDOOR, DeviceType.SIREN_INDOOR):
				devices_to_update.append(device_number)

		if self._is_central_unit_103_or_similar():
			devices_to_update.append(self._get_central_unit_lan_connection_device_number())
			devices_to_update.append(self._get_central_unit_gsm_device_number())

		for device_number in devices_to_update:
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
		for control in self.entities[EntityType.EVENT_LOGIN].values():
			if control.id in self.hass_entities:
				self.hass_entities[control.id].trigger_event(EventLoginType.WRONG_CODE)

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
				LOGGER.exception("Read error: %s", ex)
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

						# Check some devices once an hour (and on the start too)
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
					LOGGER.exception("Write error: %s", ex)

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

		if self._main_thread == threading.current_thread():
			async def callback(_) -> None:
				stream.close()

			async_call_later(self._hass, 0.1, callback)
		else:
			time.sleep(0.1)
			stream.close()

	def _open_write_stream(self):
		return open(self._serial_port, "wb", buffering=0)

	def _open_read_stream(self):
		return open(self._serial_port, "rb", buffering=0)

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
		device_id = self._get_device_id(number)

		if device_id not in self._devices_data:
			return False

		return self._devices_data[device_id][DeviceData.BATTERY] is True

	def get_device_section(self, number: int) -> int:
		device_id = self._get_device_id(number)

		return self._devices_data[device_id][DeviceData.SECTION]

	def is_central_unit_with_battery(self) -> bool:
		return self._central_unit_data[CentralUnitData.BATTERY]

	def get_central_unit_buses(self) -> List[int]:
		return self._central_unit_data[CentralUnitData.BUSES]

	def _is_device_with_state(self, number: int) -> bool:
		return self._is_device_type_with_state(self._get_device_type(number))

	@staticmethod
	def _is_device_type_with_state(device_type: DeviceType) -> bool:
		return device_type not in (
			DeviceType.KEYPAD,
			DeviceType.SIREN_OUTDOOR,
			DeviceType.ELECTRICITY_METER_WITH_PULSE_OUTPUT,
			DeviceType.RADIO_MODULE,
		)

	def _parse_sections_states_packet(self, packet: bytes) -> None:
		sections_states = self._convert_sections_states_packet_to_sections_states(packet)

		for section, section_state in sections_states.items():
			if section_state.state == SectionPrimaryState.SERVICE:
				# Service is for all sections - we can check only the first
				self.in_service_mode = True
				return

			if self._create_section(section, section_state):
				async_dispatcher_send(self._hass, self.signal_entities_added())

			self._update_entity_state(
				self._get_section_alarm_id(section),
				self._convert_jablotron_section_state_to_alarm_state(section_state, self.partially_arming_mode()),
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

		if device_number == self._get_central_unit_power_supply_device_number():
			self._parse_central_unit_power_supply_status_packet(packet)
			return

		if device_number == self._get_central_unit_gsm_device_number():
			self._parse_central_unit_gsm_status_packet(packet)
			return

		if device_number == self._get_central_unit_lan_connection_device_number():
			self._parse_central_unit_lan_connection_status_packet(packet)
			return

		device_connection = self._parse_device_connection_type_from_device_status_packet(packet)

		if device_connection == DeviceConnection.WIRELESS:
			self._parse_wireless_device_status_packet(packet)

	def _parse_central_unit_power_supply_status_packet(self, packet: bytes) -> None:
		self._parse_central_unit_info_packet(packet[4:], packet)

	def _parse_central_unit_gsm_status_packet(self, packet: bytes) -> None:
		if packet[4:5] not in (b"\xa4", b"\xd5"):
			self._log_error_with_packet("Unknown status packet of GSM", packet)
			return

		signal_strength_sensor_id = self._get_gsm_signal_strength_sensor_id()
		signal_strength = self.bytes_to_int(packet[5:6])

		self._update_entity_state(signal_strength_sensor_id, signal_strength)

	def _parse_central_unit_lan_connection_status_packet(self, packet: bytes) -> None:
		if len(packet) < 10:
			return

		self._parse_lan_connection_ip_packet(packet[6:10])

	def _parse_lan_connection_ip_packet(self, packet: bytes) -> None:
		lan_connection_ip_id = self._get_lan_connection_ip_id()

		ip_parts = []
		for packet_position in range(0, 4):
			ip_parts.append(str(self.bytes_to_int(packet[packet_position:(packet_position + 1)])))

		lan_ip = ".".join(ip_parts)

		self._add_lan_connection_ip()
		self._update_entity_state(lan_connection_ip_id, lan_ip)

	def _parse_wireless_device_status_packet(self, packet: bytes) -> None:
		device_number = self._parse_device_number_from_device_status_packet(packet)
		device_id = self._get_device_id(device_number)

		signal_strength = self._parse_device_signal_strength_from_device_status_packet(packet)
		signal_strength_sensor_id = self._get_device_signal_strength_sensor_id(device_number)

		self._update_entity_state(signal_strength_sensor_id, signal_strength)
		self._devices_data[device_id][DeviceData.SIGNAL_STRENGTH] = signal_strength

		battery_state = self._parse_device_battery_level_from_device_status_packet(packet)

		if battery_state is not None:
			self._devices_data[device_id][DeviceData.BATTERY] = True
			self._devices_data[device_id][DeviceData.BATTERY_LEVEL] = battery_state.level

			battery_problem_sensor_id = self._get_device_battery_problem_sensor_id(device_number)
			battery_level_sensor_id = self._get_device_battery_level_sensor_id(device_number)

			self._update_entity_state(battery_problem_sensor_id, STATE_OFF if battery_state.ok else STATE_ON)

			self._update_entity_state(battery_level_sensor_id, battery_state.level)
			self._device_hass_devices[device_id].battery_level = battery_state.level

		self._store_devices_data()

	def _parse_device_state_packet(self, packet: bytes) -> None:
		device_number = self._parse_device_number_from_device_state_packet(packet)

		if device_number == DeviceNumber.CENTRAL_UNIT.value:
			self._log_debug_with_packet("State packet of central unit", packet)
			return

		if device_number in (DeviceNumber.MOBILE_APPLICATION.value, DeviceNumber.USB.value):
			self._set_last_active_user_from_device_state_packet(packet, device_number)
			return

		if device_number == self._get_central_unit_lan_connection_device_number():
			self._parse_lan_connection_device_state_packet(packet)
			return

		if device_number == self._get_central_unit_gsm_device_number():
			self._parse_gsm_device_state_packet(packet)
			return

		if device_number > self._config[CONF_NUMBER_OF_DEVICES]:
			self._log_error_with_packet("State packet of unknown device", packet)
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
			self._log_error_with_packet("Unknown state packet", packet)
			return

		packet_state_binary = self._bytes_to_binary(packet[2:3])
		is_heartbeat = self.binary_to_int(packet_state_binary[4:]) == 15

		if not is_heartbeat:
			is_fault = self.binary_to_int(packet_state_binary[4:6]) == 1
			fault = DeviceFault(self.binary_to_int(packet_state_binary[6:]))

			if is_fault and fault == DeviceFault.BATTERY and not self.is_device_with_battery(device_number):
				# It's active state when device does not have battery
				is_fault = False

			if is_fault:
				if fault == DeviceFault.BATTERY:
					self._update_entity_state(
						self._get_device_battery_problem_sensor_id(device_number),
						device_state,
					)
				else:
					self._update_entity_state(
						self._get_device_problem_sensor_id(device_number),
						device_state,
					)
			elif self._is_device_with_state(device_number):
				self._update_entity_state(
					self._get_device_state_sensor_id(device_number),
					device_state,
					store_state=False,
				)
			else:
				# Ignore - probably heartbeat
				pass

		if self.is_wireless_device(device_number):
			device_signal_strength = self.bytes_to_int(packet[10:11]) * SIGNAL_STRENGTH_STEP
			self._update_entity_state(
				self._get_device_signal_strength_sensor_id(device_number),
				device_signal_strength,
			)

	def _parse_device_info_packet(self, packet: bytes) -> None:
		lan_connection_number = self._get_central_unit_lan_connection_device_number()
		gsm_device_number = self._get_central_unit_gsm_device_number()

		device_number = self._parse_device_number_from_device_info_packet(packet)

		if device_number in (lan_connection_number, gsm_device_number):
			pass
		elif device_number > self._config[CONF_NUMBER_OF_DEVICES]:
			self._log_error_with_packet("Info packet of unknown device", packet)
			return

		subpackets = self._parse_device_info_subpackets_from_device_info_packet(packet)

		for subpacket in subpackets:
			subpacket_type = subpacket[0:1]

			if subpacket_type not in DEVICE_INFO_KNOWN_SUBPACKETS:
				if subpacket_type not in DEVICE_INFO_UNKNOWN_SUBPACKETS:
					self._log_error_with_packet(
						"Unknown info subpacket type {}".format(self.format_packet_to_string(subpacket_type)),
						packet,
					)
				continue

			if subpacket_type == DEVICE_INFO_SUBPACKET_WIRELESS:
				self._update_entity_state(
					self._get_device_signal_strength_sensor_id(device_number),
					self._parse_device_signal_strength_from_device_info_subpacket(subpacket),
				)
				continue

			info_subpacket = subpacket[2:]

			if device_number == DeviceNumber.CENTRAL_UNIT.value:
				self._parse_central_unit_info_packet(info_subpacket, packet)
			elif device_number == lan_connection_number:
				self._parse_lan_connection_info_packet(info_subpacket, packet)
			elif device_number == gsm_device_number:
				self._parse_gsm_info_packet(info_subpacket, packet)
			elif not self._is_device_ignored(device_number):
				device_type = self._get_device_type(device_number)

				device_battery_state = self._parse_device_battery_level_from_device_info_packet(info_subpacket, packet)
				if device_battery_state is not None:
					if not self.is_device_with_battery(device_number):
						self._add_battery_to_device(device_number, device_battery_state)

					self._update_entity_state(
						self._get_device_battery_problem_sensor_id(device_number),
						STATE_OFF if device_battery_state.ok else STATE_ON,
					)

					self._update_entity_state(
						self._get_device_battery_level_sensor_id(device_number),
						device_battery_state.level,
					)

					if device_type in (DeviceType.SIREN_OUTDOOR, DeviceType.SIREN_INDOOR):
						self._parse_device_siren_info_packet(info_subpacket, device_number, packet)

				if device_type in (DeviceType.THERMOMETER, DeviceType.THERMOSTAT):
					self._parse_device_input_value_info_packet(info_subpacket, device_number, packet)
				elif device_type == DeviceType.SMOKE_DETECTOR:
					self._parse_device_smoke_detector_info_packet(info_subpacket, device_number, packet)
				elif device_type == DeviceType.ELECTRICITY_METER_WITH_PULSE_OUTPUT:
					self._parse_device_electricity_meter_with_pulse_info_packet(info_subpacket, device_number, packet)
				elif device_type == DeviceType.RADIO_MODULE:
					self._log_debug_with_packet("Info packet of radio module", packet)

	def _parse_device_input_value_info_packet(self, info_subpacket: bytes, device_number: int, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		for info_packet in info_packets:
			if info_packet.type == DeviceInfoType.INPUT_VALUE:
				input_type = info_packet.packet[2:3]

				# Temperature
				if input_type == b"\x00":
					modifier = Jablotron.bytes_to_int(info_packet.packet[4:5])

					if modifier >= 128:
						modifier -= 256

					temperature = round((Jablotron.bytes_to_int(info_packet.packet[3:4]) + (255 * modifier)) / 10, 1)

					self._update_entity_state(
						self._get_device_temperature_sensor_id(device_number),
						temperature,
					)
				else:
					self._log_error_with_packet(
						"Unknown input type {} of value info packet {}".format(Jablotron.format_packet_to_string(input_type), Jablotron.format_packet_to_string(info_packet.packet)),
						packet,
					)
			elif info_packet.type == DeviceInfoType.INPUT_EXTENDED:
				# Ignore
				pass
			else:
				self._log_error_with_packet(
					"Unexpected info packet {}".format(Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)

	def _parse_device_smoke_detector_info_packet(self, info_subpacket: bytes, device_number: int, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		for info_packet in info_packets:
			if info_packet.type == DeviceInfoType.SMOKE:
				self._update_entity_state(
					self._get_device_temperature_sensor_id(device_number),
					float(Jablotron.bytes_to_int(info_packet.packet[1:2])),
				)
			elif info_packet.type == DeviceInfoType.INPUT_EXTENDED:
				# Ignore
				pass
			else:
				self._log_error_with_packet(
					"Unexpected info packet {} of smoke detector".format(Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)

	def _parse_device_siren_info_packet(self, info_subpacket: bytes, device_number: int, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		for info_packet in info_packets:
			if info_packet.type not in (DeviceInfoType.POWER, DeviceInfoType.POWER_PRECISE):
				self._log_error_with_packet(
					"Unexpected info packet {} of siren".format(Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)
				continue

			channel = info_packet.packet[1:2]

			if channel == b"\x00":
				self._update_entity_state(
					self._get_device_battery_standby_voltage_sensor_id(device_number),
					self.bytes_to_float(info_packet.packet[2:3]),
				)
			elif channel == b"\x01":
				self._update_entity_state(
					self._get_device_battery_load_voltage_sensor_id(device_number),
					self.bytes_to_float(info_packet.packet[2:3]),
				)
			else:
				self._log_error_with_packet(
					"Unknown channel {} of power info packet {} of siren".format(Jablotron.format_packet_to_string(channel), Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)

	def _parse_device_electricity_meter_with_pulse_info_packet(self, info_subpacket: bytes, device_number: int, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		pulse_number = 0
		for info_packet in info_packets:
			if info_packet.type == DeviceInfoType.POWER_PRECISE:
				# We know the packet but don't know its content
				continue

			if info_packet.type != DeviceInfoType.PULSE:
				self._log_error_with_packet(
					"Unexpected info packet {} of electricity meter with pulse".format(Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)
				continue

			if info_packet.packet[1:2] != EMPTY_PACKET:
				pulses = self.bytes_to_int(info_packet.packet[1:2]) + 255 * self.bytes_to_int(info_packet.packet[2:3])

				# We have to add it dynamically
				self._add_pulse_to_electricity_meter(device_number, pulse_number)
				self._update_entity_state(
					self._get_device_pulse_sensor_id(device_number, pulse_number),
					pulses,
				)

			# We parse only first two pulse packet
			pulse_number += 1
			if pulse_number > 1:
				break

	def _parse_central_unit_info_packet(self, info_subpacket: bytes, packet: bytes) -> None:
		power_supply_and_battery_binary = Jablotron._bytes_to_binary(info_subpacket[0:1])

		self._update_entity_state(
			self._get_device_power_supply_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
			STATE_ON if power_supply_and_battery_binary[1:2] == "1" else STATE_OFF,
		)

		battery_state = self._parse_device_battery_level_from_device_info_packet(info_subpacket, packet)
		if battery_state is not None:
			if not self._central_unit_data[CentralUnitData.BATTERY]:
				self._add_battery_to_central_unit(battery_state)

			self._update_entity_state(
				self._get_device_battery_problem_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
				STATE_OFF if battery_state.ok else STATE_ON,
			)
			self._update_entity_state(
				self._get_device_battery_level_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
				battery_state.level,
			)

		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		for info_packet in info_packets:
			if info_packet.type != DeviceInfoType.POWER:
				self._log_error_with_packet("Unexpected info packet {} of central unit".format(Jablotron.format_packet_to_string(info_packet.packet)), packet)
				continue

			channel = info_packet.packet[1:2]

			if channel == b"\x00":
				self._update_entity_state(
					self._get_device_battery_load_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
					self.bytes_to_float(info_packet.packet[2:3]),
				)
			elif channel == b"\x10":
				self._update_entity_state(
					self._get_device_battery_standby_voltage_sensor_id(DeviceNumber.CENTRAL_UNIT.value),
					self.bytes_to_float(info_packet.packet[2:3]),
				)
			elif channel == b"\x11":
				# Battery in test
				pass
			elif channel in (b"\x01", b"\x02", b"\x03"):
				bus_number = self.bytes_to_int(channel)

				self._add_bus_to_central_unit(bus_number)

				self._update_entity_state(
					self._get_central_unit_bus_voltage_sensor_id(bus_number),
					self.bytes_to_float(info_packet.packet[2:3]),
				)
				self._update_entity_state(
					self._get_central_unit_bus_devices_loss_sensor_id(bus_number),
					self.bytes_to_int(info_packet.packet[3:4]),
				)
			else:
				self._log_error_with_packet(
					"Unknown channel {} of power info packet {} of central unit".format(Jablotron.format_packet_to_string(channel), Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)

	def _parse_lan_connection_info_packet(self, info_subpacket: bytes, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		for info_packet in info_packets:
			if info_packet.type != DeviceInfoType.LAN:
				self._log_error_with_packet(
					"Unexpected info packet {} of LAN connection".format(Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)
				continue

			state_binary = Jablotron._bytes_to_binary(info_packet.packet[1:2])

			lan_ok = state_binary[0:1] == "1"
			dhcp_ok = state_binary[6:7] == "1"

			self._update_entity_state(
				self._get_lan_connection_id(),
				STATE_ON if lan_ok and dhcp_ok else STATE_OFF,
			)

			self._parse_lan_connection_ip_packet(info_packet.packet[2:6])

	def _parse_gsm_info_packet(self, info_subpacket: bytes, packet: bytes) -> None:
		info_packets = self._parse_device_info_packets_from_device_info_subpacket(info_subpacket, packet)

		for info_packet in info_packets:
			if info_packet.type != DeviceInfoType.GSM:
				self._log_error_with_packet(
					"Unexpected info packet {} of GSM".format(Jablotron.format_packet_to_string(info_packet.packet)),
					packet,
				)
				continue

			state_binary = Jablotron._bytes_to_binary(info_packet.packet[5:6])

			self._update_entity_state(
				self._get_gsm_signal_sensor_id(),
				STATE_ON if state_binary[7:8] == "1" else STATE_OFF,
			)

			self._update_entity_state(
				self._get_gsm_signal_strength_sensor_id(),
				float(Jablotron.bytes_to_int(info_packet.packet[1:2])),
			)

	def _parse_lan_connection_device_state_packet(self, packet: bytes) -> None:
		lan_connection_device_number = self._get_central_unit_lan_connection_device_number()

		device_state = self._convert_jablotron_device_state_to_state(packet, lan_connection_device_number)

		if device_state is None:
			self._log_error_with_packet("Unknown state packet of LAN connection", packet)
			return

		self._update_entity_state(
			self._get_lan_connection_id(),
			STATE_ON if device_state == STATE_OFF else STATE_OFF,
		)

	def _parse_gsm_device_state_packet(self, packet: bytes) -> None:
		gsm_device_number = self._get_central_unit_gsm_device_number()

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

	def _get_central_unit_power_supply_device_number(self) -> int | None:
		if self._is_central_unit_101_or_similar():
			return 124

		return None

	def _get_central_unit_lan_connection_device_number(self) -> int | None:
		if self._is_central_unit_101_or_similar():
			return 125

		if self._is_central_unit_103_or_similar():
			return 233

		return None

	def _get_central_unit_gsm_device_number(self) -> int | None:
		if self._is_central_unit_101_or_similar():
			return 127

		if self._is_central_unit_103_or_similar():
			return 234

		return None

	def _is_central_unit_101_or_similar(self) -> bool:
		return self._central_unit.model in ("JA-101K", "JA-101K-LAN", "JA-106K-3G")

	def _is_central_unit_103_or_similar(self) -> bool:
		return self._central_unit.model in ("JA-103K", "JA-103KRY", "JA-107K")

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
			self._hass.loop.call_soon_threadsafe(
				lambda: self.hass_entities[entity_id].update_state(state)
			)
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
			and (
				self._is_section_modify_packet(packet)
				or self._is_get_sections_and_pg_outputs_states_packet(packet)
			)
		):
			return True

		if (
			self._options.get(CONF_LOG_PG_OUTPUTS_PACKETS, False)
			and (
				self._is_pg_output_toggle_packet(packet)
				or self._is_get_sections_and_pg_outputs_states_packet(packet)
			)
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
		unquie_id = self._get_unique_id()

		if unquie_id not in self._stored_data:
			self._stored_data[unquie_id] = {}

		if STORAGE_STATES_KEY not in self._stored_data[unquie_id]:
			self._stored_data[unquie_id][STORAGE_STATES_KEY] = {}

		if (
			entity_id in self._stored_data[unquie_id][STORAGE_STATES_KEY]
			and self._stored_data[unquie_id][STORAGE_STATES_KEY][entity_id] == state
		):
			return

		self._stored_data[unquie_id][STORAGE_STATES_KEY][entity_id] = state
		self._store_data_to_store_threadsafe()

	def _remove_stored_entity_state(self, entity_id: str) -> None:
		unique_id = self._get_unique_id()

		if unique_id not in self._stored_data:
			return

		if STORAGE_STATES_KEY not in self._stored_data[unique_id]:
			return

		if entity_id not in self._stored_data[unique_id][STORAGE_STATES_KEY]:
			return

		del self._stored_data[unique_id][STORAGE_STATES_KEY][entity_id]
		self._store_data_to_store_threadsafe()

	def _store_central_unit_data(self) -> None:
		unique_id = self._get_unique_id()

		if unique_id not in self._stored_data:
			self._stored_data[unique_id] = {}

		self._stored_data[unique_id][STORAGE_CENTRAL_UNIT_KEY] = self._central_unit_data
		self._store_data_to_store_threadsafe()

	def _store_devices_data(self) -> None:
		unique_id = self._get_unique_id()

		if unique_id not in self._stored_data:
			self._stored_data[unique_id] = {}

		self._stored_data[unique_id][STORAGE_DEVICES_KEY] = self._devices_data
		self._store_data_to_store_threadsafe()

	def _store_data_to_store_threadsafe(self):
		self._hass.loop.call_soon_threadsafe(
			lambda: self._store.async_delay_save(self._data_to_store)
		)

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

	def _add_lan_connection_ip(self) -> None:
		lan_connection_ip_id = self._get_lan_connection_ip_id()

		if lan_connection_ip_id in self.entities[EntityType.LAN_IP]:
			return

		self._central_unit_data[CentralUnitData.LAN_IP] = True
		self._store_central_unit_data()

		self._add_entity(
			None,
			EntityType.LAN_IP,
			lan_connection_ip_id,
		)

		async_dispatcher_send(self._hass, self.signal_entities_added())

	def _add_bus_to_central_unit(self, bus_number: int) -> None:
		if bus_number in self._central_unit_data[CentralUnitData.BUSES]:
			return

		self._central_unit_data[CentralUnitData.BUSES].append(bus_number)
		self._store_central_unit_data()

		self._add_central_unit_bus_entities(bus_number)

		async_dispatcher_send(self._hass, self.signal_entities_added())

	def _add_battery_to_central_unit(self, battery_state: JablotronBatteryState) -> None:
		self._central_unit_data[CentralUnitData.BATTERY] = True
		self._central_unit_data[CentralUnitData.BATTERY_LEVEL] = battery_state.level

		self._store_central_unit_data()

		self._add_battery_entities(DeviceNumber.CENTRAL_UNIT.value, battery_state)
		self._add_battery_voltage_entities(DeviceNumber.CENTRAL_UNIT.value)

		async_dispatcher_send(self._hass, self.signal_entities_added())

	def _add_battery_to_device(self, device_number: int, battery_state: JablotronBatteryState) -> None:
		device_id = self._get_device_id(device_number)
		device_type = self._get_device_type(device_number)

		self._devices_data[device_id][DeviceData.BATTERY] = True
		self._devices_data[device_id][DeviceData.BATTERY_LEVEL] = battery_state.level
		self._store_devices_data()

		self._add_battery_entities(device_number, battery_state)

		if device_type in (DeviceType.SIREN_OUTDOOR, DeviceType.SIREN_INDOOR):
			self._add_battery_voltage_entities(device_number)

		async_dispatcher_send(self._hass, self.signal_entities_added())

	def _add_battery_entities(self, device_number: int, battery_state: JablotronBatteryState) -> None:
		device_id = self._get_device_id(device_number)
		hass_device = None if device_number == DeviceNumber.CENTRAL_UNIT.value else self._device_hass_devices[device_id]

		self._add_entity(
			hass_device,
			EntityType.BATTERY_LEVEL,
			self._get_device_battery_level_sensor_id(device_number),
			battery_state.level,
		)

		self._add_entity(
			hass_device,
			EntityType.BATTERY_PROBLEM,
			self._get_device_battery_problem_sensor_id(device_number),
			STATE_OFF if battery_state.ok else STATE_ON,
		)

	def _add_battery_voltage_entities(self, device_number: int) -> None:
		device_id = self._get_device_id(device_number)
		hass_device = None if device_number == DeviceNumber.CENTRAL_UNIT.value else self._device_hass_devices[device_id]

		self._add_entity(
			hass_device,
			EntityType.BATTERY_STANDBY_VOLTAGE,
			self._get_device_battery_standby_voltage_sensor_id(device_number),
		)

		self._add_entity(
			hass_device,
			EntityType.BATTERY_LOAD_VOLTAGE,
			self._get_device_battery_load_voltage_sensor_id(device_number),
		)

	def _add_central_unit_bus_entities(self, bus_number: int) -> None:
		self._add_entity(
			None,
			EntityType.BUS_VOLTAGE,
			self._get_central_unit_bus_voltage_sensor_id(bus_number),
			None,
			self._get_central_unit_bus_voltage_sensor_name(bus_number),
		)

		self._add_entity(
			None,
			EntityType.BUS_DEVICES_CURRENT,
			self._get_central_unit_bus_devices_loss_sensor_id(bus_number),
			None,
			self._get_central_unit_bus_devices_loss_sensor_name(bus_number),
		)

	def _add_pulse_to_electricity_meter(self, device_number: int, pulse_number: int = 0) -> None:
		pulse_sensor_id = self._get_device_pulse_sensor_id(device_number, pulse_number)

		if pulse_sensor_id in self.entities[EntityType.PULSES]:
			# May be already added
			return

		device_id = self._get_device_id(device_number)
		hass_device = self._device_hass_devices[device_id]

		self._add_entity(
			hass_device,
			EntityType.PULSES,
			pulse_sensor_id,
		)

		async_dispatcher_send(self._hass, self.signal_entities_added())

	def _add_entity(self, hass_device: JablotronHassDevice | None, entity_type: EntityType, entity_id: str, initial_state: StateType = None, entity_name: str | None = None) -> None:
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
		LOGGER.error("{}: {}".format(Jablotron._add_device_to_log_description(description, packet), Jablotron.format_packet_to_string(packet)))

	@staticmethod
	def _log_debug_with_packet(description: str, packet: bytes) -> None:
		LOGGER.debug("{}: {}".format(Jablotron._add_device_to_log_description(description, packet), Jablotron.format_packet_to_string(packet)))

	@staticmethod
	def _add_device_to_log_description(description: str, packet: bytes) -> str:
		device_number = Jablotron._parse_device_number_from_packet(packet)

		if device_number is None:
			return description

		return "{} (device {})".format(description, device_number)

	@staticmethod
	def _is_sections_states_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_SECTIONS_STATES

	@staticmethod
	def _is_section_modify_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_UI_CONTROL and packet[2:3] == UI_CONTROL_MODIFY_SECTION

	@staticmethod
	def _is_get_sections_and_pg_outputs_states_packet(packet: bytes) -> bool:
		return packet[:1] == PACKET_COMMAND and packet[2:3] == COMMAND_GET_SECTIONS_AND_PG_OUTPUTS_STATES

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
	def _convert_sections_states_packet_to_sections_states(packet: bytes) -> Dict[int, JablotronSectionState]:
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
	def _parse_device_battery_level_from_device_status_packet(packet: bytes) -> JablotronBatteryState | None:
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
		packet_binary = Jablotron._bytes_to_binary(packet[4:6])
		return Jablotron.binary_to_int(packet_binary[2:10])

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
	def _parse_device_info_subpackets_from_device_info_packet(packet: bytes) -> List[bytes]:
		return Jablotron.get_packets_from_packet(packet[3:])

	@staticmethod
	def _parse_device_info_packets_from_device_info_subpacket(info_subpacket: bytes, packet: bytes) -> List[ParsedDeviceInfoPacket]:
		info_packets = []

		start = 2
		while start < len(info_subpacket):
			info_type_packet = info_subpacket[start:(start + 1)]

			if info_type_packet == EMPTY_PACKET:
				break

			info_type_packet_binary = Jablotron._bytes_to_binary(info_type_packet)
			info_type_int = Jablotron.binary_to_int(info_type_packet_binary[3:])

			length = Jablotron.binary_to_int(info_type_packet_binary[0:3])
			end = start + length + 1

			try:
				info_type = DeviceInfoType(info_type_int)

				if not info_type.is_unknown():
					info_packets.append(ParsedDeviceInfoPacket(info_type, info_subpacket[start:end]))

			except Exception:
				Jablotron._log_error_with_packet(
					"Unknown device info type {}".format(info_type_int),
					packet,
				)

			start = end

		return info_packets

	@staticmethod
	def _parse_device_signal_strength_from_device_info_subpacket(packet: bytes) -> JablotronBatteryState | None:
		return Jablotron.bytes_to_int(packet[2:3]) * SIGNAL_STRENGTH_STEP

	@staticmethod
	def _parse_device_battery_level_from_device_info_packet(info_packet: bytes, packet: bytes) -> JablotronBatteryState | None:
		try:
			return Jablotron._parse_device_battery_level_packet(info_packet[0:1])
		except InvalidBatteryLevel:
			Jablotron._log_debug_with_packet(
				"Unknown battery level packet of device {}".format(Jablotron._parse_device_number_from_device_info_packet(info_packet)),
				packet,
			)

			return None

	@staticmethod
	def _parse_device_battery_level_packet(packet: bytes) -> JablotronBatteryState | None:
		packet_binary = Jablotron._bytes_to_binary(packet)
		battery_level_packet = Jablotron.int_to_bytes(Jablotron.binary_to_int(packet_binary[4:]))

		if battery_level_packet == BATTERY_LEVEL_NO_BATTERY:
			return None

		if battery_level_packet == BATTERY_LEVEL_NO_CHANGE_FROM_PREVIOUS_STATE:
			return None

		if battery_level_packet not in BATTERY_LEVELS_TO_IGNORE:
			battery_level = Jablotron.bytes_to_int(battery_level_packet) * BATTERY_LEVEL_STEP
			if battery_level > 100:
				raise InvalidBatteryLevel
		else:
			battery_level = None

		battery_ok = True if packet_binary[3:4] == "0" else False

		return JablotronBatteryState(battery_ok, battery_level)

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
	def _get_section_fire_sensor_id(section: int) -> str:
		return "section_fire_sensor_{}".format(section)

	@staticmethod
	def _get_device_state_sensor_id(device_number: int) -> str:
		return "device_sensor_{}".format(device_number)

	def _get_device_sensor_name(self, device_number: int) -> str:
		return "{} (device {})".format(self._get_device_name(device_number), device_number)

	@staticmethod
	def _get_device_state_entity_type(device_type: DeviceType) -> EntityType | None:
		return DEVICE_TYPE_TO_ENTITY_TYPE[device_type] if Jablotron._is_device_type_with_state(device_type) else None

	@staticmethod
	def _get_device_problem_sensor_id(device_number: int) -> str:
		return "device_problem_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_signal_strength_sensor_id(device_number: int) -> str:
		return "device_signal_strength_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_power_supply_sensor_id(device_number: int) -> str:
		return "device_power_supply_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_battery_problem_sensor_id(device_number: int) -> str:
		return "device_battery_problem_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_battery_level_sensor_id(device_number: int) -> str:
		return "device_battery_level_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_temperature_sensor_id(device_number: int) -> str:
		return "device_temperature_sensor_{}".format(device_number)

	@staticmethod
	def _get_device_battery_standby_voltage_sensor_id(device_number: int) -> str:
		return "battery_standby_voltage_{}".format(device_number)

	@staticmethod
	def _get_device_battery_load_voltage_sensor_id(device_number: int) -> str:
		return "battery_load_voltage_{}".format(device_number)

	@staticmethod
	def _get_central_unit_bus_voltage_sensor_id(bus_number: int) -> str:
		sensor_id = "bus_voltage_{}".format(DeviceNumber.CENTRAL_UNIT.value)

		if bus_number != 1:
			sensor_id += "_bus_{}".format(bus_number)

		return sensor_id

	@staticmethod
	def _get_central_unit_bus_voltage_sensor_name(bus_number: int) -> str:
		return "BUS {} voltage".format(bus_number)

	@staticmethod
	def _get_central_unit_bus_devices_loss_sensor_id(bus_number: int) -> str:
		sensor_id = "bus_devices_loss_{}".format(DeviceNumber.CENTRAL_UNIT.value)

		if bus_number != 1:
			sensor_id += "_bus_{}".format(bus_number)

		return sensor_id

	@staticmethod
	def _get_central_unit_bus_devices_loss_sensor_name(bus_number: int) -> str:
		return "BUS {} devices loss".format(bus_number)

	@staticmethod
	def _get_device_pulse_sensor_id(device_number: int, pulse_number: int = 0) -> str:
		if pulse_number == 0:
			return "pulses_{}".format(device_number)

		return "pulses_{}_{}".format(device_number, pulse_number)

	@staticmethod
	def _get_lan_connection_id() -> str:
		return "lan"

	@staticmethod
	def _get_lan_connection_ip_id() -> str:
		return "lan_ip"

	@staticmethod
	def _get_gsm_signal_sensor_id() -> str:
		return "gsm_signal_sensor"

	@staticmethod
	def _get_gsm_signal_strength_sensor_id() -> str:
		return "gsm_signal_strength_sensor"

	@staticmethod
	def _get_pg_output_id(pg_output_number: int) -> str:
		return "pg_output_{}".format(pg_output_number)

	@staticmethod
	def _get_pg_output_name(pg_output_number: int) -> str:
		return "PG output {}".format(pg_output_number)

	@staticmethod
	def _convert_jablotron_section_state_to_alarm_state(state: JablotronSectionState, partially_arming_mode: PartiallyArmingMode) -> StateType:
		if state.state in (SectionPrimaryState.SERVICE, SectionPrimaryState.BLOCKED):
			return None

		if state.triggered:
			return STATE_ALARM_TRIGGERED

		if state.pending:
			return STATE_ALARM_PENDING

		if state.arming:
			return STATE_ALARM_ARMING

		if state.state == SectionPrimaryState.ARMED_FULL:
			return STATE_ALARM_ARMED_AWAY

		if state.state == SectionPrimaryState.ARMED_PARTIALLY:
			return STATE_ALARM_ARMED_HOME if partially_arming_mode == PartiallyArmingMode.HOME_MODE else STATE_ALARM_ARMED_NIGHT

		return STATE_ALARM_DISARMED

	@staticmethod
	def _convert_jablotron_section_state_to_problem_sensor_state(state: JablotronSectionState) -> StateType:
		return STATE_ON if state.problem or state.sabotage else STATE_OFF

	@staticmethod
	def _convert_jablotron_section_state_to_fire_sensor_state(state: JablotronSectionState) -> StateType:
		return STATE_ON if state.fire else STATE_OFF

	@staticmethod
	def _parse_jablotron_section_state(section_binary: str) -> JablotronSectionState:
		return JablotronSectionState(
			SectionPrimaryState(Jablotron.binary_to_int(section_binary[5:8])),
			arming=section_binary[0:1] == "1",
			pending=section_binary[1:2] == "1",
			triggered=section_binary[3:4] == "1" or section_binary[4:5] == "1" or section_binary[12:13] == "1" or section_binary[13:14] == "1",
			problem=section_binary[2:3] == "1",
			sabotage=section_binary[11:12] == "1",
			fire=section_binary[14:15] == "1",
		)

	@staticmethod
	def get_packets_from_packet(packet: bytes) -> List[bytes]:
		packets = []

		start = 0
		while start < len(packet):
			if packet[start:(start + 1)] == EMPTY_PACKET:
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

			if letter == EMPTY_PACKET:
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
	def create_packet_get_system_info(info_type: SystemInfo) -> bytes:
		return Jablotron.create_packet(PACKET_GET_SYSTEM_INFO, Jablotron.int_to_bytes(info_type.value))

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

	@staticmethod
	def detect_serial_port() -> str | None:
		for possible_path in os.listdir(HIDRAW_PATH):
			possible_realpath = os.path.realpath("{}/{}".format(HIDRAW_PATH, possible_path))
			if "16D6:0008" in possible_realpath:
				serial_port = "/dev/{}".format(possible_path)
				LOGGER.debug("Detected serial port: {}".format(serial_port))
				return serial_port

		return None


class JablotronEntity(Entity):

	_attr_should_poll = False
	_attr_has_entity_name = True

	def __init__(
		self,
		jablotron: Jablotron,
		control: JablotronControl,
	) -> None:
		self._jablotron: Jablotron = jablotron
		self._control: JablotronControl = control

		self._attr_unique_id = "{}.{}.{}".format(DOMAIN, self._control.central_unit.unique_id, self._control.id)

		if self._control.hass_device is None:
			self._attr_device_info = DeviceInfo(
				manufacturer="Jablotron",
				identifiers={(DOMAIN, self._control.central_unit.unique_id)},
			)
		else:
			self._attr_device_info = DeviceInfo(
				manufacturer="Jablotron",
				identifiers={(DOMAIN, self._control.hass_device.id)},
				name=self._control.hass_device.name,
				via_device=(DOMAIN, self._control.central_unit.unique_id),
			)

		self._update_attributes()

	def _update_attributes(self) -> None:
		if self._control.hass_device is not None and self._control.hass_device.battery_level is not None:
			self._attr_extra_state_attributes = {
				ATTR_BATTERY_LEVEL: self._control.hass_device.battery_level,
			}

	@property
	def control(self) -> JablotronControl:
		return self._control

	@property
	def available(self) -> bool:
		if self._jablotron.in_service_mode is True:
			return False

		if self._get_state() is None:
			return False

		return self._jablotron.last_update_success

	async def async_added_to_hass(self) -> None:
		self._jablotron.subscribe_hass_entity_for_updates(self._control.id, self)

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
