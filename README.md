# router

A command line for the Huawei HG8145V5 fiber router (an EchoLife ONT), so you can see what's on
your network and change settings without clicking through its web pages.

It also works with the HG8145X7, which serves its web interface over TLS. `status`, `devices`,
`reserved`, `wifi`, `forwards` and `pages` are tested there; `reserve`, `unreserve`, `set` and
`reboot` aren't yet.

```
$ router
router    HG8145V5, firmware V5R0xxxxxxxx, up 12d 4h
internet  Connected, 203.0.113.7 (INTERNET)
fiber     ok, receiving -21.50 dBm, sending 2.30 dBm, 48 °C
wifi      2.4 GHz on, channel 9, HomeNet
wifi      5 GHz on, channel 36, HomeNet-5G
devices   6 online, 31 remembered, 4 reserved

$ router devices
192.168.100.20   aa:bb:cc:dd:ee:01  LAN4      reserved  desktop
192.168.100.21   aa:bb:cc:dd:ee:02  wifi 5    reserved  tv
192.168.100.34   aa:bb:cc:dd:ee:03  wifi 2.4            phone

$ router wifi
2.4 GHz  on  channel 9 (auto)   HomeNet
5 GHz    on  channel 36 (auto)  HomeNet-5G

192.168.100.21   5 GHz    -25 dBm  702/866 Mbps  tv
192.168.100.34   2.4 GHz  -58 dBm  52/144 Mbps   phone
```

## Install

You need Python 3.11 or newer, and nothing else.

```
git clone https://github.com/0xmch/hg8145-cli
ln -s "$PWD"/hg8145-cli/router.py ~/bin/router
```

## Configure

Tell it how to get the password, in `~/.config/router/config.toml` (or wherever `ROUTER_CONFIG`
points). It runs that command and uses what it prints, so the password itself needn't be in a file.

```toml
password_command = ["security", "find-generic-password", "-s", "router", "-w"]   # macOS Keychain
# password_command = ["pass", "show", "router"]
# password_command = ["secret-tool", "lookup", "service", "router"]

# These two are the usual defaults, and only need setting if yours differ.
# host = "192.168.100.1"
# user = "root"
```

## Commands

| | |
|---|---|
| `router` or `router status` | model, internet, fiber, Wi-Fi, device counts |
| `router devices [-a]` | what's online, or everything it remembers |
| `router wifi` | the networks, and who's on them with what signal |
| `router reserved` | addresses reserved for devices |
| `router reserve DEVICE [IP]` | keep a device on an address, by default the one it has |
| `router unreserve DEVICE` | stop keeping it there |
| `router forwards` | port forwards |
| `router pages` | every page your login can read |
| `router page PATH` | the data on a page, as JSON, secrets left out |
| `router set PATH name=value...` | change any setting. Asks first, `-y` doesn't |
| `router reboot` | restart the router. Asks first, `-y` doesn't |

A device can be given by name, address or MAC. A name that could mean several is refused, with the
candidates listed. Most commands also take `--json`.

`router pages` and `router page` are how to find a setting that has no command of its own. The name
of a setting and its path in the tree are in the page's own JavaScript, for example
`set.cgi?x=InternetGatewayDevice.X_HW_MainUPnP` and `x.Enable` on the UPnP page.

## Good to know

- **Logging in logs you out elsewhere.** Each command logs in and out, and a login ends any other
  session of that account, so running this drops a browser that's on the admin pages.
- **The login locks after 3 bad attempts**, for a minute or so. This tries once and stops.
- **It works over plain HTTP**, as the router's own pages do. The password crosses your LAN encoded,
  not encrypted.
- **Secrets stay out of the output.** `router page` leaves out anything named like a password, key,
  PIN, user name or serial number. It goes by the field's name, so read what a page you haven't
  seen before gives you before you paste it anywhere.
- **`router set` can break your connection.** It sends what you tell it, with no checks, and the
  router's reply doesn't say whether it worked, so read the setting back afterwards.

## How it works

There's no API, but the web interface is a thin layer over a settings tree:

- **Reading.** A page holds its data as `new Thing("a", "b")`, with `function Thing(x, y)` naming
  the fields, so the data can be read without running the page.
- **Changing.** A POST to `add.cgi`, `set.cgi` or `del.cgi`, with `?x=<path in the tree>`, the
  values as `x.<name>=<value>`, and a token from `GetRandToken.asp`.
- **Logging in.** A POST to `login.cgi` with the password in base64 and a token from
  `GetRandCount.asp`. The session is the `sid` in the cookie it returns.

## Other routers

It was written against one HG8145V5, where everything has been run except `router reboot`, and
`router forwards` has only seen an empty list. Other Huawei ONTs share much of this interface, and
firmware from different ISPs shows different pages, so other models may work in part. `router pages`
shows what yours offers.

## Tests

`python3 -m unittest` runs against made-up pages and a made-up router, and never touches a real one.

## License

MIT
