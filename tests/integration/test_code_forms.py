from __future__ import annotations

from types import SimpleNamespace

from homeassistant.const import CONF_PASSWORD
from homeassistant.data_entry_flow import FlowHandler, FlowManager, FlowResultType, InvalidData
import pytest

from custom_components.jablotron100.config_flow import JablotronConfigFlow, JablotronOptionsFlow, vol
from custom_components.jablotron100.const import (
	CONF_DEVICES,
	CONF_LOG_ALL_INCOMING_PACKETS,
	CONF_NUMBER_OF_DEVICES,
	CONF_NUMBER_OF_PG_OUTPUTS,
	CONF_PARTIALLY_ARMING_MODE,
	CONF_REQUIRE_CODE_TO_ARM,
	CONF_REQUIRE_CODE_TO_DISARM,
	CONF_SERIAL_PORT,
	DeviceType,
	MAX_DEVICES,
	MAX_PG_OUTPUTS,
)


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("reconfigure", [False, True])
async def test_code_form_uses_shared_validation(hass, jablotron, reconfigure):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow._config = dict(jablotron._config)
	result = await (flow.async_step_reconfigure_settings() if reconfigure else flow.async_step_user())
	schema = result["data_schema"]
	for code in ("1234", "12345678", "12*3456", "123*345678"):
		assert schema({CONF_PASSWORD: code})[CONF_PASSWORD] == code
	for code in ("123", "123456789", "abcd", "1234abcd", "12**3456", "1234 "):
		with pytest.raises(vol.Invalid):
			schema({CONF_PASSWORD: code})
	if reconfigure:
		assert schema({CONF_PASSWORD: ""})[CONF_PASSWORD] == ""
	else:
		with pytest.raises(vol.Invalid):
			schema({CONF_PASSWORD: ""})


@pytest.fixture
def form_manager(hass):
	def create(schema):
		class SchemaFlow(FlowHandler):
			async def async_step_init(self, user_input=None):
				if user_input is not None:
					return self.async_create_entry(data=user_input)
				return self.async_show_form(step_id="init", data_schema=schema)

		class SchemaManager(FlowManager):
			async def async_create_flow(self, handler_key, *, context=None, data=None):
				return SchemaFlow()

			async def async_finish_flow(self, flow, result):
				return result

		return SchemaManager(hass)

	return create


@pytest.mark.parametrize("step,invalid_input,valid_input,error_field", [
	pytest.param("user", {CONF_PASSWORD: "abcd"}, {CONF_PASSWORD: "12*3456"}, CONF_PASSWORD, id="user-code"),
	pytest.param("user", {CONF_PASSWORD: "1234", CONF_NUMBER_OF_DEVICES: MAX_DEVICES + 1}, {CONF_PASSWORD: "1234", CONF_NUMBER_OF_DEVICES: "2"}, CONF_NUMBER_OF_DEVICES, id="user-device-range"),
	pytest.param("user", {CONF_PASSWORD: "1234", CONF_NUMBER_OF_PG_OUTPUTS: MAX_PG_OUTPUTS + 1}, {CONF_PASSWORD: "1234", CONF_NUMBER_OF_PG_OUTPUTS: "2"}, CONF_NUMBER_OF_PG_OUTPUTS, id="user-pg-range"),
	pytest.param("devices", {"device_001": "invalid"}, {"device_001": "smoke_detector"}, "device_001", id="device-selector"),
	pytest.param("reconfigure_settings", {CONF_PASSWORD: "123"}, {CONF_PASSWORD: ""}, CONF_PASSWORD, id="reconfigure-empty-code"),
	pytest.param("reconfigure_settings", {CONF_NUMBER_OF_DEVICES: 1}, {CONF_NUMBER_OF_DEVICES: "3"}, CONF_NUMBER_OF_DEVICES, id="reconfigure-preserve-minimum"),
	pytest.param("reconfigure_devices", {"device_002": "invalid"}, {}, "device_002", id="reconfigure-device-defaults"),
	pytest.param("options", {CONF_PARTIALLY_ARMING_MODE: "invalid"}, {}, CONF_PARTIALLY_ARMING_MODE, id="options-selector-defaults"),
	pytest.param("options", {CONF_REQUIRE_CODE_TO_ARM: "invalid"}, {CONF_REQUIRE_CODE_TO_ARM: True}, CONF_REQUIRE_CODE_TO_ARM, id="options-bool"),
	pytest.param("debug", {CONF_LOG_ALL_INCOMING_PACKETS: "invalid"}, {CONF_LOG_ALL_INCOMING_PACKETS: True}, CONF_LOG_ALL_INCOMING_PACKETS, id="debug-bool"),
])
async def test_all_form_schemas_use_homeassistant_validation(hass, jablotron, form_manager, step, invalid_input, valid_input, error_field):
	flow = JablotronConfigFlow()
	flow.hass = hass
	flow._config = dict(jablotron._config)
	flow._config[CONF_NUMBER_OF_DEVICES] = 2
	flow._config[CONF_DEVICES] = [DeviceType.MOTION_DETECTOR.value, DeviceType.EMPTY.value]
	if step in ("options", "debug"):
		flow = JablotronOptionsFlow(SimpleNamespace(options={
			CONF_PARTIALLY_ARMING_MODE: "home_mode",
			CONF_REQUIRE_CODE_TO_DISARM: False,
		}))
		flow.hass = hass
	form = await getattr(flow, f"async_step_{step}")()
	assert form["type"] == FlowResultType.FORM
	schema = form["data_schema"]
	assert isinstance(schema, vol.Schema)
	assert issubclass(InvalidData, vol.Invalid)

	manager = form_manager(schema)
	initial = await manager.async_init("schema-test")
	with pytest.raises(InvalidData) as error:
		await manager.async_configure(initial["flow_id"], invalid_input)
	assert error_field in error.value.schema_errors
	result = await manager.async_configure(initial["flow_id"], valid_input)
	assert result["type"] == FlowResultType.CREATE_ENTRY
	assert result["data"] == schema(valid_input)
	if step in ("devices", "reconfigure_devices"):
		assert result["data"]["device_002"] == "empty"
	if step == "reconfigure_devices":
		assert result["data"]["device_001"] == "motion_detector"
	if step == "reconfigure_settings":
		assert result["data"][CONF_PASSWORD] == ""
		assert result["data"][CONF_SERIAL_PORT] == jablotron._config[CONF_SERIAL_PORT]
	if step == "options":
		assert result["data"][CONF_PARTIALLY_ARMING_MODE] == "home_mode"
		assert result["data"][CONF_REQUIRE_CODE_TO_DISARM] is False