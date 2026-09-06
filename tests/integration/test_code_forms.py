from __future__ import annotations

from homeassistant.const import CONF_PASSWORD
import pytest
import voluptuous as vol

from custom_components.jablotron100.config_flow import JablotronConfigFlow


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