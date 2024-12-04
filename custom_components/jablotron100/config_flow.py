from __future__ import annotations
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.data_entry_flow import AbortFlow
from homeassistant.helpers import selector
import re
import time
import threading
from typing import Any, Dict, List
import voluptuous as vol
from .const import (
	AUTODETECT_SERIAL_PORT,
	CODE_MAX_LENGTH,
	CODE_MIN_LENGTH,
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
	DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
	DOMAIN,
	DeviceType,
	LOGGER,
	MAX_DEVICES,
	MAX_PG_OUTPUTS,
	NAME,
	PACKET_SYSTEM_INFO,
	PartiallyArmingMode,
	STREAM_MAX_WORKERS,
	STREAM_PACKET_SIZE,
	STREAM_TIMEOUT,
	SystemInfo,
)
from .errors import (
	ModelNotDetected,
	ModelNotSupported,
	ServiceUnavailable,
)
from .jablotron import Jablotron


def check_serial_port(serial_port: str) -> None:
	stop_event = threading.Event()
	thread_pool_executor = ThreadPoolExecutor(max_workers=STREAM_MAX_WORKERS)

	def reader_thread() -> str | None:
		detected_model = None

		stream = open(serial_port, "rb", buffering=0)

		try:
			while not stop_event.is_set():
				raw_packet = stream.read(STREAM_PACKET_SIZE)
				LOGGER.debug("Check serial port: {}".format(Jablotron.format_packet_to_string(raw_packet)))

				packets = Jablotron.get_packets_from_packet(raw_packet)
				for packet in packets:
					if (
						packet[:1] == PACKET_SYSTEM_INFO
						and Jablotron.bytes_to_int(packet[2:3]) == SystemInfo.MODEL.value
					):
						try:
							detected_model = Jablotron.decode_system_info_packet(packet)
							break
						except UnicodeDecodeError:
							# Will try again
							pass

				if detected_model is not None:
					break

				# Because of USB/IP
				time.sleep(1)

		finally:
			stream.close()

		return detected_model

	def writer_thread() -> None:
		while not stop_event.is_set():
			stream = open(serial_port, "wb", buffering=0)

			stream.write(Jablotron.create_packet_get_system_info(SystemInfo.MODEL))

			stream.close()

			time.sleep(1)

	try:
		reader = thread_pool_executor.submit(reader_thread)
		thread_pool_executor.submit(writer_thread)

		model = reader.result(STREAM_TIMEOUT)

		if model is None:
			raise ModelNotDetected

		if not re.match(r"^JA-1((0[01367])|4)", model):
			LOGGER.debug("Unsupported model: {}", model)
			raise ModelNotSupported("Model {} not supported".format(model))

	except (IndexError, FileNotFoundError, IsADirectoryError, UnboundLocalError, OSError) as ex:
		LOGGER.exception("Service unavailable: %s", ex)
		raise ServiceUnavailable

	finally:
		stop_event.set()
		thread_pool_executor.shutdown(wait=False, cancel_futures=True)


def get_devices_fields(number_of_devices: int, default_values: List | None = None) -> OrderedDict:
	if default_values is None:
		default_values = [DeviceType.EMPTY] * number_of_devices

	device_types = []
	for device_type in DeviceType:
		if device_type != DeviceType.CENTRAL_UNIT:
			device_types.append(device_type)

	fields = OrderedDict()

	for i in range(1, number_of_devices + 1):
		default_value = None

		default_value_index = i - 1
		if default_value_index < len(default_values):
			default_value = DeviceType(default_values[default_value_index])

		# vol.In(devices_values)
		fields[vol.Required("device_{:03}".format(i), default=default_value)] = selector.SelectSelector(
			selector.SelectSelectorConfig(
				options=device_types,
				mode=selector.SelectSelectorMode.DROPDOWN,
				translation_key="device_type",
			),
		)

	return fields


def create_range_validation(minimum: int, maximum: int):
	return vol.All(vol.Coerce(int), vol.Range(min=minimum, max=maximum))


class JablotronConfigFlow(ConfigFlow, domain=DOMAIN):
	_config_entry: ConfigEntry | None
	_config: Dict[str, Any] | None = None

	@staticmethod
	@callback
	def async_get_options_flow(config_entry: ConfigEntry) -> JablotronOptionsFlow:
		return JablotronOptionsFlow(config_entry)

	async def async_step_user(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		errors = {}

		if user_input is not None:

			try:
				unique_id = user_input[CONF_SERIAL_PORT]

				await self.async_set_unique_id(unique_id)
				self._abort_if_unique_id_configured()

				if user_input[CONF_SERIAL_PORT] == AUTODETECT_SERIAL_PORT:
					serial_port = Jablotron.detect_serial_port()

					if serial_port is None:
						LOGGER.error("No serial port found")
						raise ServiceUnavailable
				else:
					serial_port = user_input[CONF_SERIAL_PORT]

				check_serial_port(serial_port)

				self._config = {
					CONF_UNIQUE_ID: user_input[CONF_SERIAL_PORT],
					CONF_SERIAL_PORT: user_input[CONF_SERIAL_PORT],
					CONF_PASSWORD: user_input[CONF_PASSWORD],
					CONF_NUMBER_OF_DEVICES: user_input[CONF_NUMBER_OF_DEVICES],
					CONF_NUMBER_OF_PG_OUTPUTS: user_input[CONF_NUMBER_OF_PG_OUTPUTS],
					CONF_DEVICES: [],
				}

				if user_input[CONF_NUMBER_OF_DEVICES] == 0:
					return self.async_create_entry(title=NAME, data=self._config)

				return await self.async_step_devices()

			except AbortFlow as ex:
				return self.async_abort(reason=ex.reason)

			except ModelNotDetected:
				errors["base"] = "model_not_detected"

			except ModelNotSupported:
				errors["base"] = "model_not_supported"

			except ServiceUnavailable:
				errors["base"] = "service_unavailable"

			except Exception as ex:
				LOGGER.exception("Unknown error: %s", ex)
				LOGGER.error(
					"Unknown error connecting to %s at %s",
					NAME,
					user_input[CONF_SERIAL_PORT],
				)

				return self.async_abort(reason="unknown")

		return self.async_show_form(
			step_id="user",
			data_schema=vol.Schema(
				{
					vol.Required(CONF_SERIAL_PORT, default=AUTODETECT_SERIAL_PORT): str,
					vol.Required(CONF_PASSWORD): vol.All(str, vol.Length(min=CODE_MIN_LENGTH, max=CODE_MAX_LENGTH)),
					vol.Optional(CONF_NUMBER_OF_DEVICES, default=0): create_range_validation(0, MAX_DEVICES),
					vol.Optional(CONF_NUMBER_OF_PG_OUTPUTS, default=0): create_range_validation(0, MAX_PG_OUTPUTS),
				}
			),
			errors=errors,
		)

	async def async_step_devices(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		errors = {}

		if user_input is not None:
			try:
				devices = []
				for device_number in sorted(user_input):
					devices.append(user_input[device_number])

				self._config[CONF_DEVICES] = devices

				return self.async_create_entry(title=NAME, data=self._config)

			except Exception as ex:
				LOGGER.exception("Unknown error: %s", ex)

				return self.async_abort(reason="unknown")

		fields = get_devices_fields(self._config[CONF_NUMBER_OF_DEVICES])

		return self.async_show_form(
			step_id="devices",
			data_schema=vol.Schema(fields),
			errors=errors,
		)

	async def async_step_reconfigure(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		self._config_entry = self.hass.config_entries.async_get_entry(
			self.context["entry_id"]
		)

		self._config = dict(self._config_entry.data)

		return await self.async_step_reconfigure_settings()

	async def async_step_reconfigure_settings(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:

		if user_input is not None:
			if CONF_UNIQUE_ID not in self._config:
				self._config[CONF_UNIQUE_ID] = self._config[CONF_SERIAL_PORT]
			self._config[CONF_SERIAL_PORT] = user_input[CONF_SERIAL_PORT]

			if user_input[CONF_PASSWORD] != "":
				self._config[CONF_PASSWORD] = user_input[CONF_PASSWORD]

			self._config[CONF_NUMBER_OF_DEVICES] = user_input[CONF_NUMBER_OF_DEVICES]
			self._config[CONF_NUMBER_OF_PG_OUTPUTS] = user_input[CONF_NUMBER_OF_PG_OUTPUTS]

			if user_input[CONF_NUMBER_OF_DEVICES] > 0:
				return await self.async_step_reconfigure_devices()

			return self._finish_reconfigure()

		fields = {
			vol.Required(CONF_SERIAL_PORT, default=self._config[CONF_SERIAL_PORT]): str,
			vol.Optional(
				CONF_PASSWORD,
				default="",
			): vol.All(str, vol.Length(min=0, max=CODE_MAX_LENGTH)),
		}

		number_of_devices_validation = create_range_validation(self._config[CONF_NUMBER_OF_DEVICES], MAX_DEVICES)

		if self._config[CONF_NUMBER_OF_DEVICES] > 0:
			fields[vol.Required(CONF_NUMBER_OF_DEVICES, default=self._config[CONF_NUMBER_OF_DEVICES])] = number_of_devices_validation
		else:
			fields[vol.Optional(CONF_NUMBER_OF_DEVICES, default=self._config[CONF_NUMBER_OF_DEVICES])] = number_of_devices_validation

		configured_number_of_pg_outputs = self._config[CONF_NUMBER_OF_PG_OUTPUTS] if CONF_NUMBER_OF_PG_OUTPUTS in self._config else 0
		number_of_pg_outputs_validation = create_range_validation(0, MAX_PG_OUTPUTS)

		if configured_number_of_pg_outputs > 0:
			fields[vol.Required(CONF_NUMBER_OF_PG_OUTPUTS, default=configured_number_of_pg_outputs)] = number_of_pg_outputs_validation
		else:
			fields[vol.Optional(CONF_NUMBER_OF_PG_OUTPUTS, default=configured_number_of_pg_outputs)] = number_of_pg_outputs_validation

		return self.async_show_form(
			step_id="reconfigure_settings",
			data_schema=vol.Schema(fields),
		)

	async def async_step_reconfigure_devices(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		if user_input is not None:
			devices = []
			for device_number in sorted(user_input):
				devices.append(user_input[device_number])

			self._config[CONF_DEVICES] = devices

			return self._finish_reconfigure()

		fields = get_devices_fields(self._config[CONF_NUMBER_OF_DEVICES], self._config[CONF_DEVICES])

		return self.async_show_form(
			step_id="reconfigure_devices",
			data_schema=vol.Schema(fields),
		)

	def _finish_reconfigure(self) -> ConfigFlowResult:
		assert self._config_entry

		return self.async_update_reload_and_abort(
			self._config_entry,
			title=NAME,
			data_updates=self._config,
			reason="reconfigure_successful",
		)


class JablotronOptionsFlow(OptionsFlow):
	_options: Dict[str, Any]

	def __init__(self, config_entry: ConfigEntry) -> None:
		self._options = deepcopy(dict(config_entry.options))

	async def async_step_init(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		return self.async_show_menu(
			step_id="init",
			menu_options=["options", "debug"],
		)

	async def async_step_options(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		if user_input is not None:
			self._options[CONF_PARTIALLY_ARMING_MODE] = user_input[CONF_PARTIALLY_ARMING_MODE]
			self._options[CONF_REQUIRE_CODE_TO_DISARM] = user_input[CONF_REQUIRE_CODE_TO_DISARM]
			self._options[CONF_REQUIRE_CODE_TO_ARM] = user_input[CONF_REQUIRE_CODE_TO_ARM]

			return self._save()

		partially_arming_modes = []
		for partially_arming in PartiallyArmingMode:
			partially_arming_modes.append(partially_arming)

		return self.async_show_form(
			step_id="options",
			data_schema=vol.Schema(
				{
					vol.Required(
						CONF_PARTIALLY_ARMING_MODE,
						default=self._options.get(CONF_PARTIALLY_ARMING_MODE, PartiallyArmingMode.NIGHT_MODE.value),
					): selector.SelectSelector(
						selector.SelectSelectorConfig(
							options=partially_arming_modes,
							mode=selector.SelectSelectorMode.DROPDOWN,
							translation_key="partially_arming_mode",
						),
					),
					vol.Optional(
						CONF_REQUIRE_CODE_TO_DISARM,
						default=self._options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM),
					): bool,
					vol.Optional(
						CONF_REQUIRE_CODE_TO_ARM,
						default=self._options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM),
					): bool,
				}
			),
		)

	async def async_step_debug(self, user_input: Dict[str, Any] | None = None) -> ConfigFlowResult:
		if user_input is not None:
			self._options[CONF_LOG_ALL_INCOMING_PACKETS] = user_input[CONF_LOG_ALL_INCOMING_PACKETS]
			self._options[CONF_LOG_ALL_OUTCOMING_PACKETS] = user_input[CONF_LOG_ALL_OUTCOMING_PACKETS]
			self._options[CONF_LOG_SECTIONS_PACKETS] = user_input[CONF_LOG_SECTIONS_PACKETS]
			self._options[CONF_LOG_PG_OUTPUTS_PACKETS] = user_input[CONF_LOG_PG_OUTPUTS_PACKETS]
			self._options[CONF_LOG_DEVICES_PACKETS] = user_input[CONF_LOG_DEVICES_PACKETS]

			if (
				self._options[CONF_LOG_ALL_INCOMING_PACKETS]
				or self._options[CONF_LOG_ALL_OUTCOMING_PACKETS]
				or self._options[CONF_LOG_SECTIONS_PACKETS]
				or self._options[CONF_LOG_PG_OUTPUTS_PACKETS]
				or self._options[CONF_LOG_DEVICES_PACKETS]
			):
				self._options[CONF_ENABLE_DEBUGGING] = True
			else:
				self._options[CONF_ENABLE_DEBUGGING] = False

			return self._save()

		return self.async_show_form(
			step_id="debug",
			data_schema=vol.Schema(
				{
					vol.Optional(
						CONF_LOG_ALL_INCOMING_PACKETS,
						default=self._options.get(CONF_LOG_ALL_INCOMING_PACKETS, False),
					): bool,
					vol.Optional(
						CONF_LOG_ALL_OUTCOMING_PACKETS,
						default=self._options.get(CONF_LOG_ALL_OUTCOMING_PACKETS, False),
					): bool,
					vol.Optional(
						CONF_LOG_SECTIONS_PACKETS,
						default=self._options.get(CONF_LOG_SECTIONS_PACKETS, False),
					): bool,
					vol.Optional(
						CONF_LOG_PG_OUTPUTS_PACKETS,
						default=self._options.get(CONF_LOG_PG_OUTPUTS_PACKETS, False),
					): bool,
					vol.Optional(
						CONF_LOG_DEVICES_PACKETS,
						default=self._options.get(CONF_LOG_DEVICES_PACKETS, False),
					): bool,
				}
			),
		)

	def _save(self) -> ConfigFlowResult:
		return self.async_create_entry(title=NAME, data=self._options)
