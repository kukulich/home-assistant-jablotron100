from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD
from homeassistant.core import callback
from homeassistant.data_entry_flow import AbortFlow
import voluptuous as vol
from .const import (
	CONF_SERIAL_PORT,
	CONF_REQUIRE_CODE_TO_ARM,
	CONF_REQUIRE_CODE_TO_DISARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
	DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
	DOMAIN,
	DEFAULT_SERIAL_PORT,
	NAME,
	LOGGER,
)
from typing import Any, Dict, Optional
from .errors import (
	ModelNotDetected,
	ModelNotSupported,
	ServiceUnavailable,
)
from .jablotron import check_serial_port


class JablotronConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):

	@staticmethod
	@callback
	def async_get_options_flow(config_entry: config_entries.ConfigEntry) -> config_entries.OptionsFlow:
		return JablotronOptionsFlow(config_entry)

	async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
		errors = {}

		if user_input is not None:

			try:
				unique_id = user_input[CONF_SERIAL_PORT]

				await self.async_set_unique_id(unique_id)
				self._abort_if_unique_id_configured()

				check_serial_port(user_input[CONF_SERIAL_PORT])

				return self.async_create_entry(title=NAME, data=user_input)

			except AbortFlow as ex:
				return self.async_abort(reason=ex.reason)

			except ModelNotDetected:
				errors["base"] = "model_not_detected"

			except ModelNotSupported:
				errors["base"] = "model_not_supported"

			except ServiceUnavailable:
				errors["base"] = "service_unavailable"

			except Exception as ex:
				LOGGER.debug(format(ex))
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
					vol.Required(CONF_SERIAL_PORT, default=DEFAULT_SERIAL_PORT): str,
					vol.Required(CONF_PASSWORD): str,
				}
			),
			errors=errors,
		)


class JablotronOptionsFlow(config_entries.OptionsFlow):

	def __init__(self, config_entry: config_entries.ConfigEntry) -> None:
		self._config_entry: config_entries.ConfigEntry = config_entry

	async def async_step_init(self, user_input: Optional[Dict[str, Any]] = None):
		if user_input is not None:
			return self.async_create_entry(title=NAME, data=user_input)

		return self.async_show_form(
			step_id="init",
			data_schema=vol.Schema(
				{
					vol.Optional(
						CONF_REQUIRE_CODE_TO_DISARM,
						default=self._config_entry.options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM),
					): bool,
					vol.Optional(
						CONF_REQUIRE_CODE_TO_ARM,
						default=self._config_entry.options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM),
					): bool,
				}
			),
		)
