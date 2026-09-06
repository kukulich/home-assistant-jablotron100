from __future__ import annotations

import asyncio

from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import storage

from .const import DOMAIN


DATA_STORE = f"{DOMAIN}_store"


class JablotronStore(storage.Store):

	def __init__(self, hass: HomeAssistant, version: int) -> None:
		super().__init__(hass, version, DOMAIN)
		self.data: dict = {}
		self._loaded = False
		self._load_lock = asyncio.Lock()

	async def async_load(self) -> dict:
		async with self._load_lock:
			if not self._loaded:
				try:
					loaded = await super().async_load()
				except NotImplementedError:
					loaded = None
				self.data.update(loaded or {})
				self._loaded = True
		return self.data


@callback
def async_get_store(hass: HomeAssistant, version: int) -> JablotronStore:
	store = hass.data.get(DATA_STORE)
	if store is None:
		store = JablotronStore(hass, version)
		hass.data[DATA_STORE] = store
	return store