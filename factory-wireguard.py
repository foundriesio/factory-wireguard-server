#!/usr/bin/python3
import fcntl
import json
import logging
import os
import socket
import struct
import subprocess
import sys
import time

from argparse import ArgumentParser
from io import StringIO
from typing import Dict, Iterable, Optional, TextIO, Tuple
from urllib.parse import urlencode

import requests

logging.basicConfig(level="INFO", format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger()
logging.getLogger("requests").setLevel(logging.WARNING)

OAUTH_CLIENT_ID = "fioid_B68H03zaynCXzycBX9M3WKL7xLqJYJyf"


class WgPeer:
    def __init__(self, pubkey: str):
        self.pubkey = pubkey
        self.ip = self.latest_handshake = self.stats = ""

    def __repr__(self):
        return self.pubkey + " / " + self.ip

    @classmethod
    def iter_all(cls, intf_name: str) -> Iterable["WgPeer"]:
        out = subprocess.check_output(["wg", "show", intf_name])
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
    def __init__(
        self,
        factory: str,
        apitoken: Optional[str] = None,
        oauthcreds: Optional[str] = None,
        urlbase: str = "https://api.foundries.io",
    ):
        if apitoken:
            self._get_headers = lambda: {"OSF-TOKEN": apitoken}
        elif oauthcreds:
            self._get_headers = lambda: self._get_oauth_headers(factory, oauthcreds)
        else:
            raise ValueError("apitoken or oauthcreds required")
        self._urlbase = urlbase

    def _get_oauth_headers(self, factory: str, credsfile: str) -> str:
        try:
            with open(credsfile) as f:
                data = json.load(f)
            raise NotImplementedError
        except FileNotFoundError:
            return self._register_oauth(factory, credsfile)

    def _register_oauth(self, factory: str, credsfile: str) -> dict:
        data = {
            "client_id": OAUTH_CLIENT_ID,
            "response_type": "code",
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "scope": f"{factory}:devices:read-update {factory}:devices:read",
        }

        print("Visit this link to authorize this application:")
        url = "https://app.foundries.io/authorize?" + urlencode(data)
        print("  ", url)

        sys.stdout.write("Enter code: ")
        sys.stdout.flush()
        try:
            code = sys.stdin.readline().strip()
        except KeyboardInterrupt:
            sys.stdout.write("\n")
            sys.exit(0)

        # Get two tokens.
        # Token 1 - short-lived token with devices:read-update to update factory
        # Token 2 - long-level token with devices:read
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": OAUTH_CLIENT_ID,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "scope": factory + ":devices:read-update",
            "expires": 90,
        }

        r = requests.post("https://app.foundries.io/oauth/token", data=data)
        if not r.ok:
            sys.exit("ERROR: %s: HTTP_:%d: %s" % (r.url, r.status_code, r.text))

        update_token = r.json()["access_token"]

        del data["expires"]
        data["scope"] = factory + ":devices:read"
        r = requests.post("https://app.foundries.io/oauth/token", data=data)
        if not r.ok:
            sys.exit("ERROR: %s: HTTP_:%d: %s" % (r.url, r.status_code, r.text))

        creds = {
            "access_token": r.json()["access_token"],
            "refresh_token": r.json()["refresh_token"],
            "expires_in": r.json()["expires_in"],
            "created": time.time(),
        }
        with open(credsfile, "w") as f:
            json.dump(creds, f, indent=2)
        return {"Authorization": "Bearer " + update_token}

    def get(self, resource: str) -> dict:
        if resource.startswith("http"):
            url = resource
        else:
            url = self._urlbase + resource
        r = requests.get(url, headers=self._get_headers())
        r.raise_for_status()
        return r.json()

    def patch(self, resource: str, data: dict):
        if resource.startswith("http"):
            url = resource
        else:
            url = self._urlbase + resource
        r = requests.patch(url, headers=self._get_headers(), json=data)
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
    def iter_vpn_enabled(
        cls, factory: str, api: FactoryApi
    ) -> Iterable["FactoryDevice"]:
        items = api.get("/ota/factories/" + factory + "/wireguard-ips/")
        cls.ip_cache = {}
        for item in items:
            if item.get("enabled"):
                cls.ip_cache[item["name"]] = item["pubkey"], item["ip"]
                yield cls(item["name"], item["pubkey"], item["ip"])


# TODO - stop using wg-quick and use low-level "wg" command instead. It allows
#        us to use "wg syncconf" so that changes don't bring things down/up
class WgServer:
    def __init__(self, privkey: str, addr: str, port: int, api: "FactoryApi"):
        self.privkey = privkey
        self.api = api
        self.port = port
        self.addr = addr

    def _gen_conf(self, factory: str, f: TextIO, no_sysctl: bool):
        intf = """
[Interface]
Address = {addr}
ListenPort = {port}
PrivateKey = {key}
SaveConfig = false

PostUp = iptables -t nat -A POSTROUTING -o {intf} -j MASQUERADE
PostUp = iptables -A FORWARD -i %i -j ACCEPT
        """.format(
            key=self.privkey, addr=self.addr, port=self.port, intf="TODO"
        )
        f.write(intf.strip())
        f.write("\n")
        if not no_sysctl:
            f.write("PostUp = sysctl -q -w net.ipv4.ip_forward=1\n\n")
            f.write("PostDown = sysctl -q -w net.ipv4.ip_forward=0\n")

        intf = """
PostDown = iptables -D FORWARD -i %i -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o {intf} -j MASQUERADE
        """.format(
            intf="TODO"
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

    def gen_conf(self, factory: str, no_sysctl: bool) -> str:
        buf = StringIO()
        self._gen_conf(factory, buf, no_sysctl)
        return buf.getvalue()

    def apply_conf(self, factory: str, conf: str, intf_name: str):
        with open("/etc/wireguard/%s.conf" % intf_name, "w") as f:
            os.fchmod(f.fileno(), 0o700)
            f.write(conf)
        try:
            subprocess.check_call(["wg-quick", "down", intf_name])
        except subprocess.CalledProcessError:
            log.info("Unable to take VPN down. Assuming initial invocation")
        subprocess.check_call(["wg-quick", "up", intf_name])

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


def _assert_ip(ip: str):
    """Make sure this IP isn't already in use"""

    def ip_addr(interface: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        return socket.inet_ntoa(
            fcntl.ioctl(
                s.fileno(),
                0x8915,  # SIOCGIFADDR
                struct.pack("256s", interface[:15].encode("UTF-8")),
            )[20:24]
        )
        s.close()

    for _, interface in socket.if_nameindex():
        try:
            if ip_addr(interface) == ip:
                sys.exit("ERROR: IP Address %s is already in use" % ip)
        except OSError:
            pass


def configure_factory(args):
    if not args.endpoint:
        args.endpoint = WgServer.probe_external_ip()

    print("External Endpoint: %s:%d" % (args.endpoint, args.port))
    print("VPN Address:", args.vpnaddr)

    if not args.no_check_ip:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.bind((args.endpoint, args.port))
            s.close()
        except OSError:
            sys.exit(
                "ERROR: A UDP socket is already opened on %s:%d"
                % (args.endpoint, args.port)
            )
    _assert_ip(args.vpnaddr)

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


def enable_for_factory(args):
    configure_factory(args)
    svc = "factory-vpn-" + args.factory + ".service"
    print("Creating systemd service", svc)
    here = os.path.dirname(os.path.abspath(__file__))

    if args.apitoken:
        authparam = "-t " + args.apitoken
    else:
        authparam = "-a " + args.oauthcreds

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
ExecStart=/usr/bin/python3 ./factory-wireguard.py -n {intf} -f {factory} {authparam} -k {key} daemon
Restart=always

[Install]
WantedBy=multi-user.target
        """.format(
                here=here,
                factory=args.factory,
                authparam=authparam,
                key=args.privatekey,
                intf=args.intf_name,
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


def update_dns(factory: str, intf_name: str):
    # There's a couple of ways to infer this. This looks at the ultimates
    # source of truth - the wireguard status. The status only shows things
    # by the device's public key. So we then look at the
    # FactoryDevice.ip_cache to figure out the device name
    hosts_by_pub = {v[0]: k for k, v in FactoryDevice.ip_cache.items()}
    hosts = ""
    for peer in WgPeer.iter_all(intf_name):
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
        conf = wgserver.gen_conf(args.factory, args.no_sysctl)
        if cur_conf != conf:
            if cur_conf != "":
                log.info("Configuration changed, applying changes")
            wgserver.apply_conf(args.factory, conf, args.intf_name)
            cur_conf = conf
            update_dns(args.factory, args.intf_name)
        time.sleep(args.interval)


def enable_run(args):
    configure_factory(args)
    daemon(args)


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
    auth_group = parser.add_mutually_exclusive_group(required=True)
    auth_group.add_argument(
        "--apitoken", "-t", help="API token to access api.foundries.io"
    )
    auth_group.add_argument(
        "--oauthcreds", "-a", help="OAuth2 credentials file for api.foundries.io"
    )
    parser.add_argument(
        "--factory", "-f", required=True, help="Foundries Factory to work with"
    )
    parser.add_argument(
        "--intf-name",
        "-n",
        help="Name of wireguard interface to create. Default is fio<factory>",
    )
    parser.add_argument(
        "--privatekey",
        "-k",
        required=True,
        help="Path to private key. Generate with: wg genkey",
    )
    parser.add_argument(
        "--no-sysctl", action="store_true", help="Don't perform sysctl as PostUp/Down"
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
    p.add_argument("--no-check-ip", action="store_true", help="Don't check external IP")

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
    p = sub.add_parser(
        "enable_run",
        help="Enable configure and run wireguard server in sync with Factory devices",
    )
    p.set_defaults(func=enable_run)
    p.add_argument(
        "--interval",
        "-i",
        type=int,
        default=300,
        help="How often to sync device settings. default=%(default)d seconds",
    )
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
    p.add_argument("--no-check-ip", action="store_true", help="Don't check external IP")

    args = parser.parse_args()
    if len(args.factory) > 12 and not args.intf_name:
        sys.exit(
            "ERROR: --intf-name argument is required when factory name >12 characters"
        )
    elif not args.intf_name:
        args.intf_name = "fio" + args.factory
    if len(args.intf_name) > 15:
        sys.exit(
            "ERROR: --intf-name argument is too long. Max length is 15 characters."
        )
    return args


if __name__ == "__main__":
    args = _get_args()
    _assert_installed()
    if getattr(args, "func", None):
        if args.apitoken:
            args.api = FactoryApi(args.factory, apitoken=args.apitoken)
        else:
            args.api = FactoryApi(args.factory, oauthcreds=args.oauthcreds)
        args.func(args)
