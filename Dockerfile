FROM alpine:3.12

RUN apk update && apk upgrade
RUN apk add iptables python3 py3-requests wireguard-tools wireguard-virt openssh-client
COPY factory* /opt/

CMD /opt/factory_run.sh
