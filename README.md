# Jablotron 100+

Home Assistant custom component for JABLOTRON 100+ alarm system

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

### HACS

1. Just use [HACS](https://hacs.xyz/) (Home Assistant Community Store)  
    <small>*HACS is a third party community store and is not included in Home Assistant out of the box.*</small>

### Manual

1. [Download integration](https://github.com/kukulich/home-assistant-jablotron100/archive/master.zip)
2. Copy the folder `custom_components/jablotron100` from the zip to your config directory
3. Restart Home Assistant
4. Jablotron integration should be available in the integrations UI

## Credits

Big thanks to [plaksnor](https://github.com/plaksnor/), [Horsi70](https://github.com/Horsi70/) and [Shamshala](https://github.com/Shamshala/) for their work on previous integration.
