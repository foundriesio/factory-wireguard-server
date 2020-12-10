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

A Dockerfile is included that can be used to make the server a container.

To build the container:
~~~
 $ docker build -t factory-wireguard-server:latest .
~~~

To invoke the server:
~~~
 $ docker run -d --restart unless-stopped --cap-add=NET_ADMIN -p 5555:5555/udp --env-file=env_file --name factory-wireguard-server factory-wireguard-server
~~~

Where a file env_file (not supplied) is used to set the environment variables.
The file content should look like:
~~~
#
# Manditory variables
#
APITOKEN=<your api token>
FACTORY=<your factory name>

#
# Optional (shown with defaults)
#
# PORT=5555
# VPNADDR=10.42.42.1
# INTERVAL=300
# INTERF="fio${FACTORY}"
# unset ENDPOINT
#ENDPOINT=192.168.1.142
# unset NOCHECKIP
NOCHECKIP=--no-check-ip
# unset NOUSESYSCTL
NOUSESYSCTL=--no-sysctl
~~~
