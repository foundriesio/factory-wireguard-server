# factory-wireguard-server
A simple tool to manage Factory VPN connections to devices from an internet
connect server based on WireGuard.

## Requirements:

* Ubuntu 18.04 or newer
* python3 and python3-requests
* wireguard - the tool will explain how to install if its missing
* Port 5555 open for UDP traffic

## Quickstart

Configure factory so devices will know about this new server:
~~~
 $ ./factory-wireguard.py \
   --apitoken <api token> \  # https://app.foundries.io/settings/tokens
   --factory <factory> \
   --privatekey /root/wgpriv.key \ # where to store generated private key
   enable
~~~

Devices will now know how to establish connections to the server.

Next, keep device settings in sync with the server:
~~~
 $ ./factory-wireguard.py --apitoken <api token> --factory <factory> --privatekey /root/wgpriv.key daemon
~~~

## Accessing devices

The `daemon` script maintains keeps /etc/hosts up-to-date with each configured
device's name and IP. This allows connecting to a device named "test-device"
to simply be:
~~~
 $ ssh fio@test-device
~~~

NOTE: devices can only access the VPN server. They can't see/access each other.

## Debugging

The best way to understand what each side of the VPN is doing is by running:
~~~
 $ sudo wg show
~~~

This says what's trying to connect, what it thinks its public key is, and how
much data has transferred between each connection.
