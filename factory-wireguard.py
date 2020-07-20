#!/usr/bin/python3
import logging
import os
import subprocess
import sys
import time

from argparse import ArgumentParser
from io import StringIO
from typing import Dict, Iterable, Optional, TextIO, Tuple

import requests

logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger()
logging.getLogger("requests").setLevel(logging.WARNING)


class WgPeer:
    def __init__(self, pubkey: str):
        self.pubkey = pubkey
        self.ip = self.latest_handshake = self.stats = ""

    def __repr__(self):
        return self.pubkey + " / " + self.ip

    @classmethod
    def iter_all(cls, factory: str) -> Iterable["WgPeer"]:
        out = subprocess.check_output(["wg", "show", "fio" + factory])
        cur = None
        for line in out.decode().splitlines():
            if line.startswith("peer:"):
                if cur:
                    yield cur
                _, pubkey = line.split(" ")
                cur = cls(pubkey.strip())
            elif cur:
                try:
                    key, val = line.split(":", 1)
                except ValueError:
                    continue
                key = key.strip()
                val = val.strip()
                if key == "allowed ips":
                    cur.ip = val.split("/")[0]
                elif key == "latest handshake":
                    cur.latest_handshake = val
                elif key == "transfer":
                    cur.stats = val
        if cur:
            yield cur


class FactoryApi:
    def __init__(self, apitoken: str, urlbase: str = "https://api.foundries.io"):
        self._headers = {"OSF-TOKEN": apitoken}
        self._urlbase = urlbase

    def get(self, resource: str) -> dict:
        if resource.startswith("http"):
            url = resource
        else:
            url = self._urlbase + resource
        r = requests.get(url, headers=self._headers)
        r.raise_for_status()
        return r.json()

    def patch(self, resource: str, data: dict):
        if resource.startswith("http"):
            url = resource
        else:
            url = self._urlbase + resource
        r = requests.patch(url, headers=self._headers, json=data)
        r.raise_for_status()
        return r.json()

    def wgserver_config(self, factory: str) -> str:
        history = self.get("/ota/factories/" + factory + "/config/")["config"]
        if len(history):
            cfg = history[0]
            for f in cfg["files"]:
                if f["name"] == "wireguard-server":
                    return f["value"]
        sys.exit("Server configuration not defined in this factory")

    def device_config(self, device: str) -> Optional[dict]:
        try:
            return self.get("/ota/devices/" + device + "/config/")["config"]
        except requests.HTTPError as e:
            if e.response.status_code == 404:
                log.info("Device(%s) has no configuration", device)
            else:
                raise e
        return None


DeviceCfg = Tuple[str, str]


class FactoryDevice:
    ip_cache: Dict[str, DeviceCfg] = {}

    def __init__(self, name: str, pubkey: str, ip: str):
        self.name = name
        self.pubkey = pubkey
        self.ip = ip

    def __repr__(self):
        return self.name + " - " + self.ip

    @classmethod
    def wireguard_cfg(cls, device: str, api: FactoryApi) -> Optional[DeviceCfg]:
        cfg = cls.ip_cache.get(device)
        if cfg:
            return cfg
        url = "https://api.foundries.io/ota/devices/"
        url += device + "/config/"
        cfg_history = api.device_config(device)
        if cfg_history and len(cfg_history):
            for f in cfg_history[0]["files"]:
                if f["name"] == "wireguard-client":
                    pub = ip = None
                    enabled = True
                    for line in f["value"].splitlines():
                        if line.startswith("address"):
                            _, ip = line.split("=", 1)
                        elif line.startswith("pubkey"):
                            _, pub = line.split("=", 1)
                        elif line.startswith("enabled"):
                            enabled = line != "enabled=0"

                    if pub and ip and enabled:
                        cls.ip_cache[device] = pub, ip
                        return pub, ip
        return None

    @classmethod
    def iter_vpn_enabled(
        cls, factory: str, api: FactoryApi
    ) -> Iterable["FactoryDevice"]:
        data = api.get("/ota/devices/?factory=" + factory)
        while True:
            for d in data["devices"]:
                cfg = cls.wireguard_cfg(d["name"], api)
                if cfg:
                    yield cls(d["name"], cfg[0], cfg[1])

            next_url = d.get("next")
            if not next_url:
                break
            data = api.get(next_url)


# TODO - stop using wg-quick and use low-level "wg" command instead. It allows
#        us to use "wg syncconf" so that changes don't bring things down/up
class WgServer:
    def __init__(self, privkey: str, addr: str, port: int, api: "FactoryApi"):
        self.privkey = privkey
        self.api = api
        self.port = port
        self.addr = addr

    def _gen_conf(self, factory: str, f: TextIO):
        intf = """
[Interface]
Address = {addr}
ListenPort = {port}
PrivateKey = {key}
SaveConfig = false

PostUp = iptables -t nat -A POSTROUTING -o {intf} -j MASQUERADE
PostUp = iptables -A FORWARD -i %i -j ACCEPT
PostUp = sysctl -q -w net.ipv4.ip_forward=1

PostDown = sysctl -q -w net.ipv4.ip_forward=0
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {intf} -j MASQUERADE
        """.format(
            key=self.privkey, addr=self.addr, port=self.port, intf="TODO"
        )
        f.write(intf.strip())
        f.write("\n")

        for device in FactoryDevice.iter_vpn_enabled(factory, self.api):
            peer = """# {name}
[Peer]
PublicKey = {key}
AllowedIPs = {ip}
            """.format(
                name=device.name, key=device.pubkey, ip=device.ip
            )
            f.write(peer.strip())
            f.write("\n")

    def gen_conf(self, factory: str) -> str:
        buf = StringIO()
        self._gen_conf(factory, buf)
        return buf.getvalue()

    def apply_conf(self, factory: str, conf: str):
        with open("/etc/wireguard/fio%s.conf" % factory, "w") as f:
            os.fchmod(f.fileno(), 0o700)
            f.write(conf)
        try:
            subprocess.check_call(["wg-quick", "down", "fio" + factory])
        except subprocess.CalledProcessError:
            log.info("Unable to take VPN down. Assuming initial invocation")
        subprocess.check_call(["wg-quick", "up", "fio" + factory])

    @staticmethod
    def probe_external_ip():
        r = requests.get("http://api.ipify.org")
        r.raise_for_status()
        return r.text

    @classmethod
    def gen_key(cls) -> Tuple[bytes, bytes]:
        priv = subprocess.check_output(["wg", "genkey"])
        return priv, cls.derive_pubkey(priv)

    @staticmethod
    def derive_pubkey(priv: bytes) -> bytes:
        return subprocess.run(
            ["wg", "pubkey"], input=priv, stdout=subprocess.PIPE
        ).stdout

    @classmethod
    def load_from_factory(cls, api: FactoryApi, factory: str, pkey: str) -> "WgServer":
        buf = api.wgserver_config(factory)
        addr = port = None
        for line in buf.splitlines():
            k, v = line.split("=", 1)
            k = k.strip()
            if k == "enabled" and v.strip() == "0":
                log.error("Server config is not enabled in this factory")
                sys.exit(1)
            elif k == "endpoint":
                _, v = v.split(":")
                port = int(v)
            elif k == "server_address":
                addr = v.strip()
        if addr and port:
            return cls(pkey, addr, port, api)
        log.error("Invalid server configuratio in factory: " + buf)
        sys.exit(1)


def enable_for_factory(args):
    if not args.endpoint:
        args.endpoint = WgServer.probe_external_ip()

    print("External Endpoint: %s:%d" % (args.endpoint, args.port))
    print("VPN Address:", args.vpnaddr)

    try:
        with open(args.privatekey, mode="rb") as f:
            priv = f.read().strip()
            pub = WgServer.derive_pubkey(priv).decode()
    except FileNotFoundError:
        print("Generating private key for VPN server...")
        priv, pub = WgServer.gen_key()
        pub = pub.strip().decode()
        with open(args.privatekey, mode="wb") as f:
            f.write(priv)

    cfgfile = """
endpoint={endpoint}:{port}
server_address={server_address}
pubkey={pub}
    """.format(
        endpoint=args.endpoint, server_address=args.vpnaddr, pub=pub, port=args.port
    )
    data = {
        "reason": "Enable Wireguard for factory",
        "files": [
            {
                "name": "wireguard-server",
                "unencrypted": True,
                "value": cfgfile.strip(),
                "on-changed": ["/usr/share/fioconfig/handlers/factory-config-vpn"],
            },
        ],
    }

    try:
        print("Registring with foundries.io...")
        args.api.patch("/ota/factories/%s/config/" % args.factory, data)
    except requests.HTTPError as e:
        msg = "ERROR: Unable to configure factory: HTTP_%d\n%s" % (
            e.response.status_code,
            e.response.text,
        )
        sys.exit(msg)

    svc = "factory-vpn-" + args.factory + ".service"
    print("Creating systemd service", svc)
    here = os.path.dirname(os.path.abspath(__file__))
    with open("/etc/systemd/system/" + svc, "w") as f:
        f.write(
            """
[Unit]
Description=Factory VPN Daemon
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory={here}
ExecStart=/usr/bin/python3 ./factory-wireguard.py -f {factory} -t {token} -k {key} daemon
Restart=always

[Install]
WantedBy=multi-user.target
        """.format(
                here=here,
                factory=args.factory,
                token=args.apitoken,
                key=args.privatekey,
            )
        )
    try:
        subprocess.check_call(["systemctl", "enable", svc])
    except subprocess.CalledProcessError:
        sys.exit(1)
    try:
        subprocess.check_call(["systemctl", "start", svc])
    except subprocess.CalledProcessError:
        sys.exit(1)
    print("Service is running. Logs can be viewed with: journalctl -fu", svc)


def update_dns(factory: str):
    # There's a couple of ways to infer this. This looks at the ultimates
    # source of truth - the wireguard status. The status only shows things
    # by the device's public key. So we then look at the
    # FactoryDevice.ip_cache to figure out the device name
    hosts_by_pub = {v[0]: k for k, v in FactoryDevice.ip_cache.items()}
    hosts = ""
    for peer in WgPeer.iter_all(factory):
        host = hosts_by_pub[peer.pubkey]
        hosts += peer.ip + "\t" + host + "\n"

    with open("/etc/hosts") as f:
        content = f.read()

    start_header = "## Factory(%s) VPN Lookups\n" % factory
    end_header = "## END Factory(%s) VPN Lookups\n" % factory
    idx = content.find(start_header)
    if idx != -1:
        new = content[:idx] + start_header
        new += hosts
        endidx = content.find(end_header)
        if endidx != -1:
            content = new + content[endidx:]
        else:
            log.warning("Did not find '%s' in /etc/hosts", end_header)
            content = new + end_header

    else:
        content += "\n" + start_header
        content += hosts
        content += end_header

    with open("/etc/hosts", "w") as f:
        f.write(content)


def daemon(args):
    with open(args.privatekey) as f:
        pkey = f.read().strip()

    log.info("Creating initial server configuration")
    wgserver = WgServer.load_from_factory(args.api, args.factory, pkey)

    cur_conf = ""
    while True:
        log.info("Looking for factory config changes")
        conf = wgserver.gen_conf(args.factory)
        if cur_conf != conf:
            if cur_conf != "":
                log.info("Configuration changed, applying changes")
            wgserver.apply_conf(args.factory, conf)
            cur_conf = conf
            update_dns(args.factory)
        time.sleep(args.interval)


def _assert_installed():
    if os.path.exists("/usr/bin/wg-quick"):
        return
    print("ERROR: Wireguard is not installed. You may install by running:")
    with open("/etc/os-release") as f:
        for line in f:
            if line.startswith("VERSION_ID="):
                _, ver, _ = line.split('"', 2)
                if float(ver) < 19.10:
                    print(" sudo add-apt-repository ppa:wireguard/wireguard")
                    print(" sudo apt-get update")
                break
    print(" sudo apt-get install wireguard")
    sys.exit(1)


def _get_args():
    parser = ArgumentParser(description="Manage a Wireguard VPN for Factory devices")
    parser.add_argument(
        "--apitoken", "-t", required=True, help="API token to access api.foundries.io"
    )
    parser.add_argument(
        "--factory", "-f", required=True, help="Foundries Factory to work with"
    )
    parser.add_argument(
        "--privatekey",
        "-k",
        required=True,
        help="Path to private key. Generate with: wg genkey",
    )
    sub = parser.add_subparsers(help="sub-command help")

    p = sub.add_parser("enable", help="Enable Wireguard VPN for factory")
    p.set_defaults(func=enable_for_factory)
    p.add_argument(
        "--port",
        "-p",
        type=int,
        default=5555,
        help="External port for clients to connect to. Default=%(default)d",
    )
    p.add_argument("--endpoint", "-e", help="External IP devices will connect to")
    p.add_argument(
        "--vpnaddr",
        "-v",
        default="10.42.42.1",
        help="VPN address for this server. Default=%(default)s",
    )

    p = sub.add_parser(
        "daemon", help="Keep wireguard server in sync with Factory devices"
    )
    p.set_defaults(func=daemon)
    p.add_argument(
        "--interval",
        "-i",
        type=int,
        default=300,
        help="How often to sync device settings. default=%(default)d seconds",
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = _get_args()
    _assert_installed()
    if getattr(args, "func", None):
        args.api = FactoryApi(args.apitoken)
        args.func(args)
