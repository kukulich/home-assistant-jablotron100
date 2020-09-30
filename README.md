Installation
---

1. Connect the USB cable to Jablotron central unit
2. Restart the Home Assistant OS
3. Use the following command line to identify the appropriate device:

    ```
    $ dmesg | grep usb
    $ dmesg | grep hid
    ```

    The cable should be connected as `/dev/hidraw[x]`, `/dev/ttyUSB0` or similar.

4. [Download integration](https://github.com/kukulich/home-assistant-jablotron100/archive/master.zip)
5. Create folder `custom_components` in your config directory
6. Copy the folder `jablotron100` from the zip to this folder
7. Restart Home Assistant
8. Jablotron integration should be available in the integrations UI
9. Use the port found in step 3

