#!/bin/sh

set -e

INTERFKEY=
INTERVALKEY=
VPNADDRKEY=
ENDPOINTKEY=
PORTKEY=

if [ -z ${APITOKEN} ]
then
  echo "ERROR: token not set" >&2
  exit 1
fi

if [ -z ${FACTORY} ]
then
  echo "ERROR: factory not set" >&2
fi

if [ -n "${INTERF}" ]
then
  INTERFKEY=--intf-name
fi

if [ -n "${INTERVAL}" ]
then
  INTERVALKEY=--interval
fi

if [ -n "${VPNADDR}" ]
then
  VPNADDRKEY=--vpnaddr
fi

if [ -n "${ENDPOINT}" ]
then
  ENDPOINTKEY=--endpoint
fi

if [ -n "${PORT}" ]
then
  PORTKEY=--port
fi

/opt/factory-wireguard.py -f ${FACTORY} -t ${APITOKEN} -k /root/wgpriv.key ${INTERFKEY} ${INTERF} ${NOUSESYSCTL} enable_run ${NOCHECKIP} ${INTERVALKEY} ${INTERVAL} ${VPNADDRKEY} ${VPNADDR} ${ENDPOINTKEY} ${ENDPOINT} ${PORTKEY} ${PORT}
