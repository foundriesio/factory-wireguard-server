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

Some servers could be behind router or firewall before reaching the internet.
If you know the port is available on the external router and you get the error:
~~~
 ERROR: A UDP socket is already opened on <external ip>:<external port>
~~~

Then you can do this configure step:
~~~
 $ ./factory-wireguard.py \
   --apitoken <api token> \  # https://app.foundries.io/settings/tokens
   --factory <factory> \
   --privatekey /root/wgpriv.key \ # where to store generated private key
   --no-check-ip \
   enable
~~~

Which will allow the endpoint to be used without a verification check.

## Advanced configuration

A docker-compose.yml is included that can be used to make the server a container.

To build the container:
~~~
 $ docker-compose build
~~~

The Server requires FACTORY and APITOKEN environment variables to be set and can
be done in a .env file all other variables are optional as listed in the compose file.

To invoke the server:
~~~
 $ docker-compose up -d
~~~
