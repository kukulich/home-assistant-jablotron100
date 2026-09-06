# Testing

Run from the repository root in a Python 3.14 virtual environment.
No alarm panel is needed.

## Packet tests

Without Home Assistant:

```sh
python -m pip install -r requirements_test.txt
python -m pytest
```

## Full suite

Use a separate environment with Home Assistant installed:

```sh
python -m pip install --upgrade -r requirements_integration_test.txt
python -m pip check
python -m pytest --ha-integration
```

To pin the minimum version declared in `hacs.json`, replace the install command with:

```sh
python -m pip install -r requirements_integration_test.txt "homeassistant==2026.9.1"
```

## CI

CI runs packet tests, mypy, and the full suite on Linux with the minimum
Home Assistant version from `hacs.json` and the latest stable release.