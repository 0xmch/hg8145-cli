#!/usr/bin/env python3
"""router: a command line for the Huawei HG8145V5 fiber router.

It has no API, and on the LAN it answers only through its web interface. That interface is a thin
layer over a settings tree, so this does what its pages do:

  read    a page holds its data as `new Thing("a", "b")`, with `function Thing(x, y)` naming them
  change  POST add.cgi, set.cgi or del.cgi with ?x=<path in the tree>, x.<name>=<value>, and a token

The login locks after 3 bad attempts, so this never retries one. Passwords, keys and serial numbers
never get printed. The README describes the configuration.
"""
import argparse
import base64
import contextlib
import ipaddress
import json
import os
import re
import shlex
import ssl
import subprocess
import sys
import tomllib
import urllib.error
import urllib.parse
import urllib.request

CONFIG = os.environ.get("ROUTER_CONFIG") or os.path.expanduser("~/.config/router/config.toml")
DEFAULTS = {"host": "192.168.100.1", "user": "root"}  # how these routers usually come
TOKEN_PAGE = "/html/ssmp/common/GetRandToken.asp"
DEVICES_PAGE = "/html/bbsp/common/GetLanUserDevInfo.asp"
RESERVED_PAGE = "/html/bbsp/dhcpstatic/dhcpstatic.asp"
LAN_PAGE = "/html/bbsp/dhcpservercfg/dhcp2.asp"
RESERVED_TREE = "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DHCPStaticAddress"
WIFI_PAGE = "/html/amp/wlaninfo/wlaninfo.asp"
WIFI_CLIENTS = "/html/amp/wlaninfo/getassociateddeviceinfo.asp"
FORWARDS_PAGE = "/html/bbsp/portmapping/portmappingnew.asp"
INFO_PAGE = "/html/ssmp/deviceinfo/deviceinfo.asp"
OPTICS_PAGE = "/html/amp/opticinfo/opticinfo.asp"
WAN_LIST = "/html/bbsp/common/getwanlist.asp"
WAN_FIELDS = "/html/bbsp/common/getWanDynamicData.asp"
REBOOT = ("/set.cgi?x=InternetGatewayDevice.X_HW_DEBUG.SSP.DBSave&y=InternetGatewayDevice.X_HW_DEBUG.SMP.DM.ResetBoard"
          "&RequestFile=html/ssmp/cfgfile/cfgfileroot.asp")

CALL = re.compile(r'new\s+(\w+)\s*\(\s*((?:"(?:[^"\\]|\\.)*"\s*,?\s*)+)\)')
STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
SIGNATURE = re.compile(r"function\s+(\w+)\s*\(([^)]*)\)")
ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})|\\(.)", re.S)
SECRET = re.compile(r"pass|psk|kpp|key|secret|pwd|token|pin|serial|specsn|user|manufacture", re.I)


class Error(Exception):
    pass


def load_config(path=CONFIG):
    config = dict(DEFAULTS)
    try:
        with open(path, "rb") as fh:
            config.update(tomllib.load(fh))
    except FileNotFoundError:
        pass
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise Error(f"{path}: {e}") from e
    return config


def read_password(config):
    """Whatever password_command prints. What it says is never repeated, in case it's the password."""
    command = config.get("password_command")
    if not command:
        raise Error(f"no way to get the password: set password_command in {CONFIG}")
    argv = shlex.split(command) if isinstance(command, str) else command
    try:
        done = subprocess.run(argv, capture_output=True, text=True)
    except OSError as e:
        raise Error(f"password_command couldn't run: {e}") from e
    if done.returncode != 0:
        raise Error(f"password_command failed (exit {done.returncode})")
    return done.stdout.rstrip("\n")


def unescape(raw):
    text = ESCAPE.sub(lambda m: chr(int(m.group(1), 16)) if m.group(1) else m.group(2), raw)
    try:
        return text.encode("latin-1").decode("utf-8")
    except (UnicodeEncodeError, UnicodeDecodeError):
        return text


def objects(page, signatures=""):
    """Every `new Thing("a", "b")` on a page, named by `function Thing(x, y)`, which can be
    elsewhere. Pages repeat their rows, with timers that have moved on in between, so a row with
    a place in the settings tree comes back once, as first seen."""
    fields = {name: [a.strip() for a in args.split(",")] for name, args in SIGNATURE.findall(signatures + page)}
    found = {}
    seen = set()
    for name, args in CALL.findall(page):
        if name in fields:
            row = dict(zip(fields[name], (unescape(v).strip() for v in STRING.findall(args))))
            key = (name, row.get("domain") or row.get("Domain") or tuple(row.items()))
            if key not in seen:
                seen.add(key)
                found.setdefault(name, []).append(row)
    return found


def without_secrets(found):
    """The same, with anything that could be a credential or an identity left out."""
    clean = {}
    for name, rows in found.items():
        if not SECRET.search(name):
            clean[name] = [{k: v for k, v in row.items() if not SECRET.search(k)} for row in rows]
    return clean


def tls_port(front):
    """Newer firmware answers plain http with nothing but a page sending the browser to TLS, on the
    port this returns. A login page may mention the port too, but it has the login form."""
    found = re.search(r"var SSLPort\s*=\s*'(\d+)'", front)
    return found.group(1) if found and "txt_Username" not in front else None


def unverified_tls():
    """That firmware's certificate comes from Huawei's own CA and names the model, not an address,
    so there's nothing to check it against."""
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def login_state(front):
    """(locked, bad attempts, attempts allowed), by the login page's own rule. Its countdown runs
    after any bad attempt, but it only locks once the attempts reach the limit."""
    values = dict(re.findall(r"var (\w+) = '([^']*)'", front))
    bad, other, left = (int(values.get(name) or 0) for name in ("LoginTimes", "ModeCheckTimes", "LockLeftTime"))
    limit = int(values.get("errloginlockNum") or 3)
    return values.get("FailStat") == "1" or ((bad >= limit or other >= limit) and left > 0), bad, limit


class Router:
    """One logged-in session, which logs out at the end. A login ends any other session of the
    same account, so using this logs a browser out of the admin page."""

    def __init__(self, config, password=None):
        self.config = config
        self.host = "http://" + config["host"]
        self.password = password
        self.cookie = "Cookie=body:Language:english:id=-1"
        self.opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=unverified_tls()))

    def request(self, path, fields=None):
        data = None if fields is None else urllib.parse.urlencode(fields).encode()
        headers = {"Cookie": self.cookie, "Referer": self.host + "/", "User-Agent": "Mozilla/5.0", "X-Requested-With": "XMLHttpRequest"}
        try:
            with self.opener.open(urllib.request.Request(self.host + path, data=data, headers=headers), timeout=15) as reply:
                return reply.headers, reply.read().decode("utf-8", "replace").lstrip("﻿")
        except urllib.error.HTTPError as reply:
            if reply.code in (301, 302, 303):
                return reply.headers, ""
            if reply.code == 403:
                raise Error(f"{path}: refused. The session ended, or this login can't see that page") from reply
            raise Error(f"{path}: HTTP {reply.code}") from reply
        except OSError as e:
            raise Error(f"no answer from {self.host}: {e}") from e

    def get(self, path):
        return self.request(path)[1]

    def post(self, path, fields=None):
        return self.request(path, fields or {})[1]

    def __enter__(self):
        front = self.get("/")
        port = tls_port(front)
        if port:
            self.host = f"https://{self.config['host']}:{port}"
            front = self.get("/")
        locked, _, _ = login_state(front)
        if locked:
            raise Error("the login is locked after bad attempts. Try again in a minute")
        token = self.post("/asp/GetRandCount.asp").strip()
        password = self.password if self.password is not None else read_password(self.config)
        headers, _ = self.request("/login.cgi", {
            "UserName": self.config["user"],
            "PassWord": base64.b64encode(password.encode()).decode(),
            "Language": "english",
            "x.X_HW_Token": token,
        })
        for cookie in headers.get_all("Set-Cookie") or []:
            found = re.match(r"Cookie\w*=[^;]*sid=[^;]+", cookie)  # Cookie= or, over TLS, CookieHttps=
            if found:
                self.cookie = found.group(0)
                return self
        _, bad, limit = login_state(self.get("/"))
        raise Error(f"the router refused the login ({bad} of {limit} bad attempts before it locks). "
                    "Not retrying. Is the password right?")

    def __exit__(self, *_):
        with contextlib.suppress(Error):  # a restart, for one, takes the session with it
            self.post("/logout.cgi?RequestFile=html/logout.html", {"x.X_HW_Token": self.token()})

    def token(self):
        return self.post(TOKEN_PAGE).strip()

    def change(self, verb, query, fields):
        """add, set or del. The reply says little, so whoever calls this checks the result."""
        self.post(f"/{verb}.cgi?{query}", {**fields, "x.X_HW_Token": self.token()})

    def devices(self):
        rows = objects(self.get(DEVICES_PAGE)).get("USERDevice", [])
        return sorted(rows, key=lambda d: ipaddress.ip_address(d["IpAddr"] or "0.0.0.0"))

    def reserved(self):
        rows = objects(self.get(RESERVED_PAGE)).get("stDhcp", [])
        return sorted(rows, key=lambda r: ipaddress.ip_address(r["ipAddress"]))

    def lan(self):
        rows = objects(self.get(LAN_PAGE)).get("stipaddr", [])
        if not rows:
            raise Error("couldn't find the router's own network")
        row = next((x for x in rows if x.get("ipaddr") == self.config["host"]), rows[0])
        return ipaddress.ip_network(f"{row['ipaddr']}/{row['subnetmask']}", strict=False)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_):
        return None


def same_mac(a, b):
    return a.lower().replace("-", ":") == b.lower().replace("-", ":")


def find_device(devices, query):
    """By address, MAC or name. Phones with changing MACs leave a trail of old entries behind
    them, so one that's online beats any that aren't."""
    q = query.lower()
    matches = [d for d in devices if d["IpAddr"] == q or same_mac(d["MacAddr"], q) or d["HostName"].lower() == q]
    matches = matches or [d for d in devices if q in d["HostName"].lower()]
    matches = [d for d in matches if d["DevStatus"] == "Online"] or matches
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise Error(f"no device matches {query}")
    raise Error(f"{query} could be: " + ", ".join(f"{d['HostName'] or '(no name)'} {d['IpAddr']} {d['MacAddr']}" for d in matches))


def band(channel):
    return "2.4 GHz" if int(channel or 0) <= 14 else "5 GHz"


def link(port):
    """SSID1-4 are the 2.4 GHz networks and SSID5-8 the 5 GHz ones."""
    found = re.fullmatch(r"SSID(\d+)", port)
    if not found:
        return port
    return "wifi 2.4" if int(found.group(1)) <= 4 else "wifi 5"


def duration(seconds):
    days, rest = divmod(int(seconds), 86400)
    hours, rest = divmod(rest, 3600)
    return f"{days}d {hours}h" if days else f"{hours}h {rest // 60}m"


def table(rows):
    rows = [[str(cell) for cell in row] for row in rows]
    widths = [max(map(len, column)) for column in zip(*rows)] if rows else []
    return ["  ".join(cell.ljust(width) for cell, width in zip(row, widths)).rstrip() for row in rows]


def show(args, data, lines):
    print(json.dumps(data, indent=2, ensure_ascii=False) if args.json else "\n".join(lines))


def confirm(args, question):
    if args.yes:
        return
    if not sys.stdin.isatty():
        raise Error(f"{question} Needs -y when nobody is there to answer.")
    if input(f"{question} [y/N] ").strip().lower() != "y":
        raise Error("left as it was")


def cmd_status(r, args):
    page = r.get(INFO_PAGE)
    info = objects(page)["stDeviceInfo"][0]
    uptime = re.search(r"dev_uptime = '(\d+)'", page)
    wan = objects(r.post(WAN_LIST), r.get(WAN_FIELDS))
    internet = [w for rows in wan.values() for w in rows if "INTERNET" in w.get("ServiceList", "") or "INTERNET" in w.get("Name", "")]
    optics = objects(r.get(OPTICS_PAGE)).get("stOpticInfo", [{}])[0]
    wifi = [w for w in objects(r.get(WIFI_PAGE)).get("stWlan", []) if w.get("ssid")]
    devices = r.devices()
    online = sum(d["DevStatus"] == "Online" for d in devices)
    data = {
        "model": info["ModelName"], "firmware": info["SoftwareVersion"],
        "uptime_s": int(uptime.group(1)) if uptime else None,
        "internet": [{"name": w.get("Name"), "status": w.get("ConnectionStatus") or w.get("Status"), "ip": w.get("IPAddress") or w.get("ExternalIPAddress")} for w in internet],
        "fiber": {"link": optics.get("LinkStatus"), "rx_dbm": optics.get("revOpticPower"), "tx_dbm": optics.get("transOpticPower"), "temp_c": optics.get("temperature")},
        "wifi": [{"band": band(w["Channel"]), "ssid": w["ssid"], "on": w["enable"] == "1", "channel": w["Channel"]} for w in wifi],
        "devices": {"online": online, "remembered": len(devices), "reserved": len(r.reserved())},
    }
    lines = [("router", f"{data['model']}, firmware {data['firmware']}" + (f", up {duration(data['uptime_s'])}" if uptime else ""))]
    lines += [("internet", f"{w['status']}, {w['ip']} ({w['name']})") for w in data["internet"]] or [("internet", "no connection found")]
    fiber = data["fiber"]
    lines.append(("fiber", f"{fiber['link']}, receiving {fiber['rx_dbm']} dBm, sending {fiber['tx_dbm']} dBm, {fiber['temp_c']} °C"))
    lines += [("wifi", f"{w['band']} {'on' if w['on'] else 'off'}, channel {w['channel']}, {w['ssid']}") for w in data["wifi"]]
    lines.append(("devices", f"{online} online, {len(devices)} remembered, {data['devices']['reserved']} reserved"))
    show(args, data, table(lines))


def cmd_devices(r, args):
    reserved = {row["macAddress"].lower() for row in r.reserved()}
    rows = [d for d in r.devices() if args.all or d["DevStatus"] == "Online"]
    data = [{"ip": d["IpAddr"], "mac": d["MacAddr"], "name": d["HostName"], "link": link(d["Port"]), "online": d["DevStatus"] == "Online", "reserved": d["MacAddr"].lower() in reserved} for d in rows]
    lines = [[d["ip"], d["mac"], d["link"], "reserved" if d["reserved"] else "", *(["online" if d["online"] else "offline"] if args.all else []), d["name"] or "(no name)"] for d in data]
    show(args, data, table(lines))


def cmd_wifi(r, args):
    page = r.get(WIFI_PAGE)
    networks = [w for w in objects(page).get("stWlan", []) if w.get("ssid")]
    clients = objects(r.post(WIFI_CLIENTS), page).get("stAssociatedDevice", [])
    names = {d["MacAddr"].lower(): d for d in r.devices()}
    data = {"networks": [{"band": band(w["Channel"]), "ssid": w["ssid"], "on": w["enable"] == "1", "channel": w["Channel"], "auto_channel": w.get("AutoChannelEnable") == "1", "standard": w.get("X_HW_Standard")} for w in networks], "clients": []}
    for c in clients:
        mac = c.get("AssociatedDeviceMACAddress", "")
        if ":" not in mac:
            continue  # the page's blank placeholder
        known = names.get(mac.lower(), {})
        network = next((w for w in networks if c["domain"].startswith(w["domain"] + ".")), {})
        data["clients"].append({"name": known.get("HostName", ""), "ip": c.get("AssociatedDeviceIPAddress") or known.get("IpAddr", ""), "mac": mac, "band": band(network.get("Channel", 0)), "rssi_dbm": c.get("X_HW_RSSI"), "snr": c.get("X_HW_SNR"), "rx_mbps": c.get("X_HW_RxRate"), "tx_mbps": c.get("X_HW_TxRate")})
    lines = table([[n["band"], "on" if n["on"] else "off", f"channel {n['channel']}" + (" (auto)" if n["auto_channel"] else ""), n["ssid"]] for n in data["networks"]])
    if data["clients"]:
        lines += [""] + table([[c["ip"], c["band"], f"{c['rssi_dbm']} dBm", f"{c['rx_mbps']}/{c['tx_mbps']} Mbps", c["name"] or c["mac"]] for c in sorted(data["clients"], key=lambda c: int(c["rssi_dbm"] or 0), reverse=True)])
    show(args, data, lines)


def cmd_reserved(r, args):
    names = {d["MacAddr"].lower(): d["HostName"] for d in r.devices()}
    data = [{"ip": row["ipAddress"], "mac": row["macAddress"], "name": names.get(row["macAddress"].lower(), "")} for row in r.reserved()]
    show(args, data, table([[d["ip"], d["mac"], d["name"] or "(not seen lately)"] for d in data]))


def cmd_reserve(r, args):
    device = find_device(r.devices(), args.device)
    ip = args.ip or device["IpAddr"]
    try:
        address = ipaddress.ip_address(ip)
    except ValueError as e:
        raise Error(f"{ip} isn't an address") from e
    lan = r.lan()
    if address not in lan or ip == "0.0.0.0":
        raise Error(f"{ip} isn't on {lan}")
    for row in r.reserved():
        if same_mac(row["macAddress"], device["MacAddr"]):
            raise Error(f"{device['MacAddr']} already has {row['ipAddress']}")
        if row["ipAddress"] == ip:
            raise Error(f"{ip} is already reserved for {row['macAddress']}")
    r.change("add", f"x={RESERVED_TREE}&RequestFile=html/bbsp/dhcpstatic/dhcpstatic.asp", {"x.Yiaddr": ip, "x.Chaddr": device["MacAddr"], "x.Enable": "1"})
    if not any(same_mac(row["macAddress"], device["MacAddr"]) and row["ipAddress"] == ip for row in r.reserved()):
        raise Error("the router didn't take it: the reservation isn't in its list")
    print(f"{ip} is reserved for {device['HostName'] or device['MacAddr']}")


def cmd_unreserve(r, args):
    q = args.device
    rows = r.reserved()
    row = next((x for x in rows if x["ipAddress"] == q or same_mac(x["macAddress"], q)), None)
    if row is None:
        device = find_device(r.devices(), q)
        row = next((x for x in rows if same_mac(x["macAddress"], device["MacAddr"])), None)
    if row is None:
        raise Error(f"nothing reserved for {q}")
    r.change("del", f"x={RESERVED_TREE}&RequestFile=html/bbsp/dhcpstatic/dhcpstatic.asp", {row["domain"]: ""})
    if any(same_mac(x["macAddress"], row["macAddress"]) for x in r.reserved()):
        raise Error("the router didn't take it: the reservation is still in its list")
    print(f"{row['ipAddress']} is no longer reserved for {row['macAddress']}")


def cmd_forwards(r, args):
    found = objects(r.get(FORWARDS_PAGE))
    data = []
    for rule in found.get("stPortMap", []):
        for ports in found.get("stPortMappingPortList", []):
            if ports["domain"].startswith(rule["domain"] + "."):
                data.append({"name": rule.get("Description"), "on": rule.get("ProtMapEnabled") == "1", "to": rule.get("InClient"), "protocol": ports.get("Protocol"), "external": ports.get("ExternalPort"), "internal": ports.get("InternalPort")})
    show(args, data, table([[d["protocol"], f"{d['external']} -> {d['to']}:{d['internal']}", "on" if d["on"] else "off", d["name"]] for d in data]) or ["no port forwards"])


def cmd_set(r, args):
    fields = {}
    for pair in args.settings:
        name, equals, value = pair.partition("=")
        if not equals:
            raise Error(f"{pair} isn't name=value")
        fields[f"x.{name}"] = value
    confirm(args, f"Set {', '.join(args.settings)} on {args.path}?")
    r.change("set", f"x={args.path}&RequestFile={INFO_PAGE.lstrip('/')}", fields)
    print("sent. The router doesn't say whether it took it, so read it back with `router page`")


def cmd_reboot(r, args):
    confirm(args, "Restart the router? Everything here loses the network for a few minutes.")
    r.post(REBOOT, {"x.X_HW_Token": r.token()})
    print("restarting")


def cmd_pages(r, args):
    menu = r.post("/asp/getMenuArray.asp")
    data = [{"name": name, "page": url} for name, url in re.findall(r'name:\s*"([^"]+)"[^{}\[\]]*?url:\s*"([^"]+)"', menu)]
    show(args, data, table([[d["name"], d["page"]] for d in data]))


def cmd_page(r, args):
    path = args.path if args.path.startswith("/") else "/" + args.path
    data = without_secrets(objects(r.get(path)))
    print(json.dumps(data, indent=2, ensure_ascii=False))


def parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print JSON")
    top = argparse.ArgumentParser(prog="router", description="A Huawei HG8145V5 router from the command line. With no command, its status.")
    sub = top.add_subparsers(dest="command")

    def command(name, run, text, *arguments):
        p = sub.add_parser(name, help=text, description=text, parents=[common])
        for flags, options in arguments:
            p.add_argument(*flags, **options)
        p.set_defaults(run=run)

    yes = (("-y", "--yes"), {"action": "store_true", "help": "don't ask first"})
    device = (("device",), {"help": "name, address or MAC"})
    command("status", cmd_status, "model, internet, fiber, Wi-Fi, device counts")
    command("devices", cmd_devices, "what's online", (("-a", "--all"), {"action": "store_true", "help": "and everything it remembers"}))
    command("wifi", cmd_wifi, "the networks, and who's on them with what signal")
    command("reserved", cmd_reserved, "addresses reserved for devices")
    command("reserve", cmd_reserve, "keep a device on an address", device, (("ip",), {"nargs": "?", "help": "default: the one it has now"}))
    command("unreserve", cmd_unreserve, "stop keeping a device on an address", device)
    command("forwards", cmd_forwards, "port forwards")
    command("pages", cmd_pages, "every page this login can read")
    command("page", cmd_page, "the data on a page, as JSON, secrets left out", (("path",), {}))
    command("set", cmd_set, "change any setting: a path in the tree, then name=value. Asks first", (("path",), {}), (("settings",), {"nargs": "+", "metavar": "name=value"}), yes)
    command("reboot", cmd_reboot, "restart the router. Asks first", yes)
    return top


def main():
    args = parser().parse_args()
    if not args.command:
        args = parser().parse_args(["status"])
    try:
        with Router(load_config()) as r:
            args.run(r, args)
    except Error as e:
        sys.exit(f"router: {e}")
    except BrokenPipeError:
        pass


if __name__ == "__main__":
    main()
