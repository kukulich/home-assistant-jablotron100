# hidraw-tcp-proxy

Exposes the Jablotron JA-100 USB cable (HID device `16d6:0008`) over TCP so
that the `jablotron100` integration can run on a host that does not have the
cable attached (for example a Home Assistant VM that must stay live-migratable).

Typical reason: Proxmox VE cannot live-migrate a VM with a USB device passed
through, so a Home Assistant VM with the JA-100 cable cannot be part of a
Proxmox HA setup. Moving the cable to a separate always-on box (such as a
Raspberry Pi) and reading it over TCP removes the USB dependency from the VM.

Protocol: both directions use frames `!H` (2-byte big-endian length) + payload.
Each HID input report (64 B) from the device is sent to every connected client
as one frame; each frame from a client is written to the device as one report.

## Install (Debian / Raspberry Pi OS, Python 3.10+, stdlib only)

```sh
sudo mkdir -p /opt/hidraw-tcp-proxy
sudo cp hidraw_tcp_proxy.py /opt/hidraw-tcp-proxy/
sudo cp hidraw-tcp-proxy.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now hidraw-tcp-proxy
```

The device must not be bound to `usbip-host` on the same machine (unbind it or
disable `usbipd` first), otherwise `/dev/hidrawN` will not exist.

## Security

The connection is **plain TCP: not encrypted and not authenticated**. Anyone
who can reach the port can read the alarm state and send commands to the
control panel, and anyone on the network path can watch or alter the traffic.
Never expose the port to the internet. Keep the proxy and Home Assistant on a
trusted network segment, or connect them over a VPN (e.g. WireGuard), and
restrict access as below.

## Access control

Limit who can connect in two layers:

1. **`--allow`** in the proxy: only listed addresses or networks may connect
   (repeatable or comma-separated, IPv4/IPv6, CIDR). Other clients are closed
   right after `accept()` and logged at most once per minute per address.
   Without `--allow` every client is accepted and a warning is logged at start.

   ```sh
   hidraw_tcp_proxy.py --port 8765 --allow 10.0.0.6,10.0.0.21 --allow 10.0.0.10/31
   ```

2. **Host firewall** (e.g. nftables) allowing the port only from the same
   addresses, so other clients never reach the process at all:

   ```nft
   table inet jablotron {
     set allowed4 { type ipv4_addr; elements = { 10.0.0.6, 10.0.0.21 } }
     chain input {
       type filter hook input priority filter; policy accept;
       iifname "lo" accept
       tcp dport 8765 ip saddr @allowed4 accept
       tcp dport 8765 counter drop
     }
   }
   ```

## Home Assistant side

In the Jablotron 100 integration set the serial port to `tcp://<host>:8765`
(IPv6: `tcp://[<address>]:8765`; the port defaults to 8765).

When the cable is unplugged or the proxy host is unreachable, the proxy closes
all connections and refuses new ones until the device is back. The integration
marks its entities unavailable and keeps reconnecting, so the proxy port can
also be watched with a plain TCP monitor.

The integration opens a short-lived connection for each write, so frequent
connects and disconnects in the proxy debug log are expected.

## Typical setup

Tested with a JA-101K-LAN, the USB cable on a Raspberry Pi (Raspberry Pi OS,
Python 3.10+) and Home Assistant OS in a Proxmox VE VM, including live migration of
the VM while connected.
