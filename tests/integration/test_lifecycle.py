from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import pytest

from custom_components.jablotron100 import PLATFORMS, async_unload_entry


pytestmark = pytest.mark.asyncio


@pytest.mark.parametrize("unload_ok", [False, True])
async def test_unload_only_stops_instance_after_platforms_unload(hass, unload_ok):
	instance = Mock()
	entry = SimpleNamespace(runtime_data=instance)
	with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(return_value=unload_ok)) as unload:
		assert await async_unload_entry(hass, entry) is unload_ok
		unload.assert_awaited_once_with(entry, PLATFORMS)
	if unload_ok:
		instance.shutdown.assert_called_once_with()
	else:
		instance.shutdown.assert_not_called()
	assert entry.runtime_data is instance


async def test_platform_unload_exception_leaves_instance_running(hass):
	instance = Mock()
	entry = SimpleNamespace(runtime_data=instance)
	with patch.object(hass.config_entries, "async_unload_platforms", new=AsyncMock(side_effect=RuntimeError("Synthetic unload failure"))):
		with pytest.raises(RuntimeError, match="Synthetic unload failure"):
			await async_unload_entry(hass, entry)
	instance.shutdown.assert_not_called()