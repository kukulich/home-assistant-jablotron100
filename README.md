[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg?style=for-the-badge)](https://github.com/hacs/default)

# Jablotron 100+

Home Assistant custom component for JABLOTRON 100+ alarm system.

Tested with JA-100K, JA-101K, JA-101K-LAN, JA-103K, JA-103KRY, JA-106K-3G, JA-107K and JA-14K.


## Features

### Sections

- States are reported to Home Assistant.
- You can arm/disarm all sections. Supported states are `arm_away` (= armed) and `arm_night`/`arm_home` (choose in options what means "armed partially" for you).
- Event `jablotron100_wrong_code` is triggered when wrong code is inserted in Home Assistant.
- Problem in a section is reported in specific "problem" sensor.

### Devices

- Devices with two states (on/off, active/inactive, open/closed etc.) are supported.
- Sabotage or problem of the device is supported in specific "problem" sensor.
- Temperature is reported for thermostats, thermometers and smoke detectors.
- Pulses are reported for electricity meters with pulse output.
- Signal strength is reported for wireless devices.
- Battery level is reported for devices with battery.
- Model, hardware and firmware versions are shown in device information when reported by a device.

### PG outputs

- States are reported to Home Assistant.
- It's possible to turn on/off all PG outputs.

### Central unit

- Power supply state and overall problem are reported as binary sensors.
- BUS voltage and BUS devices current are reported per detected BUS.
- Battery presence, battery level, standby and load voltages are reported when the central unit has a backup battery.
- LAN connection state and (when available) the LAN IP address are reported for supported central units.
- GSM signal availability and signal strength are reported for supported central units.
- A `wrong code` event entity records failed authorisation attempts; the same condition also fires the `jablotron100_wrong_code` event on the bus.


## Before installation

Requires Home Assistant 2026.10.0 or newer.

1. Connect the USB cable to Jablotron central unit
2. Restart the Home Assistant OS

## Installation

- If you use code with a prefix, insert the code with the asterisk, e.g. `12*3456`.
- Use code of administrator to make devices work. If you cannot use code of administrator, or you don't want to use devices, set the number of devices to 0.
- You have to set devices in the same order as you see them in your J-Link/F-Link/mobile application. Ignore the central unit on position 0. The number of devices is the highest position to include, not the number of physical devices in use. Set unoccupied positions to **Empty** without renumbering the other devices.
- If you want to use PG outputs, the user of the code has to have rights to control the PG outputs. Set the number of PG outputs to 0 to ignore them.


Serial port should be automatically detected. If not, you can detect it manually and set it during integration installation.

The default value `auto` makes the integration probe `/sys/class/hidraw` on every start and pick the device exposing the Jablotron USB vendor/product ID (`16D6:0008`). Prefer `auto` over a fixed `/dev/hidrawN` path — when other USB HID peripherals are connected to the host, the kernel's hidraw numbering can change between reboots.

```
$ dmesg | grep usb
$ dmesg | grep hid
```

The cable should be connected as `/dev/hidraw[x]`, `/dev/ttyUSB0` or similar.

The integration only opens existing character devices. A missing USB device must
not be replaced by a regular file, and regular files are rejected without being
modified.

#### Recovering a stale device path

Older versions could create a regular file at the device path while the USB cable
was unplugged. If the log reports that the serial port is not a character device,
stop Home Assistant (or its container) and inspect the configured or detected path
on the host with `ls -l`. A valid device starts with `c`; a regular file starts
with `-`. Only if the path is confirmed to be the stale regular file, remove that
file and reconnect the USB cable so the system recreates the character device.
Then start Home Assistant again. Do not remove a valid device node. The integration
does not delete or recreate device paths automatically.


### HACS

1. Install the integration via [HACS](https://hacs.xyz/) (Home Assistant Community Store)  
    <small>*HACS is a third party community store and is not included in Home Assistant out of the box.*</small>
2. Restart Home Assistant
3. Jablotron integration should be available in the integrations UI

### Manual

1. [Download integration](https://github.com/kukulich/home-assistant-jablotron100/releases/)
2. Copy the folder `custom_components/jablotron100` from the zip to your config directory
3. Restart Home Assistant
4. Jablotron integration should be available in the integrations UI


### Reconfigure

To change the serial port, code, number of devices or PG outputs without losing your existing configuration, open the integration on the *Devices & Services* page and choose *Reconfigure*. Leave the password field empty to keep the previously stored code. Per-device type assignments are preserved across reconfiguration.

Device discovery requests section assignments in inclusive ranges of up to 122 positions, so installations with higher or non-sequential occupied positions do not need renumbering. It combines replies by their starting position and still requires a status reply and a section assignment for every configured, non-ignored device. A failed discovery does not replace the previous device cache.

If device discovery times out, the error reports missing status replies, the received section-map coverage (or received/requested ranges for larger installations), and positions missing from the map. Compare those positions with F-Link/J-Link and change only positions that are actually unoccupied to **Empty** using *Reconfigure*. The total number of positions can remain unchanged. There is no need to remove the integration or clear its cache to correct a position assignment.


## Check

1. Try to arm/disarm all sections
2. Try to activate all devices if possible (open/close door/window, move ahead of motion sensor etc.) and check if Home Assistant see the state changes
3. Check log - it should be empty when everything works
4. Does any problem occur? Report [issue](https://github.com/kukulich/home-assistant-jablotron100/issues) or join [Discord](https://discord.gg/bNmaB6n)


## Services

### `jablotron100.reset_problem`

Locally turns the selected `problem` binary sensor back to off without waiting for the central unit to clear the underlying condition. Useful for one-shot conditions that you have already acknowledged. Only entities with `device_class: problem` from this integration are accepted.

```yaml
service: jablotron100.reset_problem
target:
  entity_id: binary_sensor.section_1_problem_sensor
```

Even if everything works for you, you can join the [Discord](https://discord.gg/bNmaB6n).
We would be happy:
 - If you report model of you Jablotron central unit, so we know that integration works on another model
 - If you can test some things (e.g. LAN), so we can make the integration more robust

The communication in Discord is mostly in Czech or Slovak but don't be afraid - you can use English as well.


## Debugging
1. Enable debug logging for the Jablotron intergation via the [logger](https://www.home-assistant.io/integrations/logger/) integration by adding the following lines to the `configuration.yaml` file.
```
logger:
  default: info
  logs: 
    custom_components.jablotron100: debug
```

2. Enable debug logging in the Jablotron integration. Go to the Integration page of your Home Assistant and click on the `Configure` button belonging to the Jablotron integration and then select `Debugging` to specify specific debugging options, such as `Log all incoming packets`. Finish the configuration by pressing the `Submit` button.
3. After enabling 1. and 2., the home assistant log should contain debug log of the Jablotron integration, e.g.,
```
2022-02-17 10:57:19 DEBUG (ThreadPoolExecutor-2_0) [custom_components.jablotron100] Incoming: 801a0cffffffff010001002820010027ffffffffffffffffffffffff
2022-02-17 10:57:19 DEBUG (ThreadPoolExecutor-2_0) [custom_components.jablotron100] Incoming: 5203820113
```
4. Restart Home Assistant

## Development

See [Testing](tests/README.md) for packet tests, tests with real Home Assistant,
and the minimum/latest Home Assistant CI matrix.

## Credits

Big thanks to [plaksnor](https://github.com/plaksnor/), [Horsi70](https://github.com/Horsi70/) and [Shamshala](https://github.com/Shamshala/) for their work on previous integration.
