[![hacs_badge](https://img.shields.io/badge/HACS-Default-orange.svg?style=for-the-badge)](https://github.com/hacs/default)

# Jablotron 100+

Home Assistant custom component for JABLOTRON 100+ alarm system

Tested with JA-101K, JA-101K-LAN, JA-103K, JA-103KRY, JA-106K-3G, JA-107K

## Preparation

1. Connect the USB cable to Jablotron central unit
2. Restart the Home Assistant OS
3. Use the following command line to identify the port:

    ```
    $ dmesg | grep usb
    $ dmesg | grep hid
    ```

    The cable should be connected as `/dev/hidraw[x]`, `/dev/ttyUSB0` or similar.

## Installation

- Use code of administrator to make devices work. If you cannot use code of administrator, or you don't want to use devices, set the number of devices to zero.
- You have to set devices in the same order as you see them in your J-Link/F-Link/mobile application. Ignore the central unit on position 0.
- If you want to use PG outputs, the user of the code has to have rights to control the PG outputs. Set the number of PG outputs to zero to ignore them.

### HACS

1. Just use [HACS](https://hacs.xyz/) (Home Assistant Community Store)  
    <small>*HACS is a third party community store and is not included in Home Assistant out of the box.*</small>

### Manual

1. [Download integration](https://github.com/kukulich/home-assistant-jablotron100/releases/)
2. Copy the folder `custom_components/jablotron100` from the zip to your config directory
3. Restart Home Assistant
4. Jablotron integration should be available in the integrations UI

## Check

1. Try to arm away/arm night/disarm all sections
2. Try to activate all devices if possible (open/close door/window, move ahead of motion sensor etc.) and check if Home Assistant see the state changes
3. Check log - it should be empty when everything works
4. Does any problem occur? Report [issue](https://github.com/kukulich/home-assistant-jablotron100/issues) or join [Discord](https://discord.gg/bNmaB6n)

Even if everything works for you, you can join the [Discord](https://discord.gg/bNmaB6n).
We would be happy:
 - If you report model of you Jablotron central unit, so we know that integration works on another model
 - If you can test some things (e.g. LAN), so we can make the integration more robust

The communication in Discord is mostly in Czech or Slovak but don't be afraid - you can use English as well.

## Credits

Big thanks to [plaksnor](https://github.com/plaksnor/), [Horsi70](https://github.com/Horsi70/) and [Shamshala](https://github.com/Shamshala/) for their work on previous integration.
