"""router.py against made-up pages and a made-up router. Nothing here talks to a real one."""
import argparse
import base64
import contextlib
import http.server
import io
import os
import tempfile
import threading
import unittest
import urllib.parse

import router as R


def device(ip, mac, name, status="Online", port="LAN4"):
    return {"IpAddr": ip, "MacAddr": mac, "HostName": name, "DevStatus": status, "Port": port}


class Pages(unittest.TestCase):
    def test_rows_are_named_by_their_function_and_unescaped(self):
        page = r'function T(domain, a, b) {} var x = new Array(new T("d\x2e1", "caf\xc3\xa9", " spaced "), null);'
        self.assertEqual(R.objects(page)["T"], [{"domain": "d.1", "a": "café", "b": "spaced"}])

    def test_the_function_can_be_on_another_page(self):
        self.assertEqual(R.objects('new T("1")', "function T(a) {}")["T"], [{"a": "1"}])

    def test_a_repeated_row_comes_back_once_even_if_its_timer_moved(self):
        page = 'function T(domain, lease) {} new T("d.1", "100"); new T("d.2", "5"); new T("d.1", "99");'
        self.assertEqual(R.objects(page)["T"], [{"domain": "d.1", "lease": "100"}, {"domain": "d.2", "lease": "5"}])

    def test_rows_outside_the_tree_are_only_merged_when_identical(self):
        page = 'function T(a) {} new T("1"); new T("2"); new T("1");'
        self.assertEqual(R.objects(page)["T"], [{"a": "1"}, {"a": "2"}])

    def test_code_that_builds_objects_is_not_data(self):
        self.assertEqual(R.objects('function T(a) {} new T(getValue("x"));'), {})

    def test_secrets_are_left_out(self):
        found = {
            "stPreSharedKey": [{"domain": "d", "psk": "s3cret", "kpp": "s3cret"}],
            "stWEPKey": [{"domain": "d", "value": "s3cret"}],
            "stWpsPin": [{"domain": "d", "DevicePassword": "s3cret"}],
            "stDeviceInfo": [{"domain": "d", "SerialNumber": "s3cret", "ModelName": "M"}],
            "WanPPP": [{"domain": "d", "Username": "s3cret", "Password": "s3cret", "Name": "w"}],
            "StRadiusAccount": [{"domain": "d", "SecondarySecret": "s3cret", "Enable": "1"}],
        }
        self.assertNotIn("s3cret", str(R.without_secrets(found)))
        self.assertEqual(R.without_secrets(found)["stDeviceInfo"], [{"domain": "d", "ModelName": "M"}])

    def test_the_lock_follows_the_login_pages_rule(self):
        page = "var LoginTimes = '%s'; var errloginlockNum = '3'; var LockLeftTime = '%s'; var ModeCheckTimes = '0'; var FailStat = '%s';"
        self.assertEqual(R.login_state(page % ("0", "0", "0")), (False, 0, 3))
        self.assertEqual(R.login_state(page % ("1", "59", "0")), (False, 1, 3), "a countdown alone isn't a lock")
        self.assertEqual(R.login_state(page % ("3", "59", "0")), (True, 3, 3))
        self.assertEqual(R.login_state(page % ("3", "0", "0")), (False, 3, 3), "the lock is over")
        self.assertTrue(R.login_state(page % ("0", "0", "1"))[0])


class Finding(unittest.TestCase):
    devices = [
        device("10.0.0.2", "aa:aa:aa:aa:aa:01", "Phone-9", "Offline"),
        device("10.0.0.3", "aa:aa:aa:aa:aa:02", "Phone-9"),
        device("10.0.0.4", "aa:aa:aa:aa:aa:03", "plug-a"),
        device("10.0.0.5", "aa:aa:aa:aa:aa:04", "plug-b"),
        device("10.0.0.6", "aa:aa:aa:aa:aa:05", ""),
    ]

    def find(self, query):
        return R.find_device(self.devices, query)["IpAddr"]

    def test_by_address_mac_or_name(self):
        self.assertEqual(self.find("10.0.0.4"), "10.0.0.4")
        self.assertEqual(self.find("AA-AA-AA-AA-AA-03"), "10.0.0.4")
        self.assertEqual(self.find("PLUG-B"), "10.0.0.5")

    def test_what_is_online_beats_an_old_entry_of_the_same_name(self):
        self.assertEqual(self.find("phone"), "10.0.0.3")

    def test_an_old_entry_can_still_be_named_by_its_address(self):
        self.assertEqual(self.find("10.0.0.2"), "10.0.0.2")

    def test_it_never_guesses(self):
        with self.assertRaisesRegex(R.Error, "could be"):
            self.find("plug")
        with self.assertRaisesRegex(R.Error, "no device"):
            self.find("toaster")

    def test_an_empty_name_matches_nothing_by_accident(self):
        with self.assertRaises(R.Error):
            self.find("zzz")


class Config(unittest.TestCase):
    def write(self, text):
        handle, path = tempfile.mkstemp(suffix=".toml")
        self.addCleanup(os.remove, path)
        with os.fdopen(handle, "w") as fh:
            fh.write(text)
        return path

    def test_no_file_means_the_usual_defaults(self):
        self.assertEqual(R.load_config("/nonexistent/config.toml"), R.DEFAULTS)

    def test_the_file_overrides_them(self):
        config = R.load_config(self.write('host = "10.0.0.1"\n'))
        self.assertEqual((config["host"], config["user"]), ("10.0.0.1", R.DEFAULTS["user"]))

    def test_a_broken_file_is_an_error(self):
        with self.assertRaises(R.Error):
            R.load_config(self.write("host = \n"))

    def test_the_password_comes_from_the_command_in_either_form(self):
        self.assertEqual(R.read_password({"password_command": ["echo", "s3cret"]}), "s3cret")
        self.assertEqual(R.read_password({"password_command": "echo 's3 cret'"}), "s3 cret")

    def test_no_command_says_what_to_set(self):
        with self.assertRaisesRegex(R.Error, "password_command"):
            R.read_password({})

    def test_a_failing_command_never_repeats_what_it_printed(self):
        with self.assertRaises(R.Error) as caught:
            R.read_password({"password_command": ["sh", "-c", "echo s3cret; echo s3cret >&2; exit 3"]})
        self.assertNotIn("s3cret", str(caught.exception))
        with self.assertRaisesRegex(R.Error, "couldn't run"):
            R.read_password({"password_command": ["/nonexistent/command"]})


class Words(unittest.TestCase):
    def test_links_and_bands(self):
        self.assertEqual([R.link("SSID1"), R.link("SSID5"), R.link("LAN4")], ["wifi 2.4", "wifi 5", "LAN4"])
        self.assertEqual([R.band("9"), R.band("36")], ["2.4 GHz", "5 GHz"])


class FakeRouter(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def reply(self, body, code=200, cookie=None):
        self.send_response(code)
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(("﻿" + body).encode())

    def authorised(self):
        return "sid=abc" in self.headers.get("Cookie", "")

    def do_GET(self):
        s = self.server
        path = self.path.split("?")[0]
        if path == "/":
            self.reply(f"var LoginTimes = '{s.bad}'; var errloginlockNum = '3'; var LockLeftTime = '{s.left}'; var ModeCheckTimes = '0';")
        elif not self.authorised():
            self.reply("", 403)
        elif path == R.DEVICES_PAGE:
            rows = ", ".join(f'new USERDevice("d{i}", "{d["IpAddr"]}", "{d["MacAddr"]}", "{d["Port"]}", "{d["DevStatus"]}", "{d["HostName"]}")' for i, d in enumerate(s.devices))
            self.reply(f"function USERDevice(Domain,IpAddr,MacAddr,Port,DevStatus,HostName) {{}} {rows};")
        elif path == R.LAN_PAGE:
            self.reply('function stipaddr(domain,enable,ipaddr,subnetmask) {} new stipaddr("d", "1", "10.0.0.1", "255.255.255.0");')
        elif path == R.RESERVED_PAGE:
            rows = ", ".join(f'new stDhcp("{R.RESERVED_TREE}.{i}", "1", "{ip}", "{mac}")' for i, (ip, mac) in s.reserved.items())
            self.reply(f"function stDhcp(domain,Enable,ipAddress,macAddress) {{}} {rows};")
        else:
            self.reply("", 404)

    def do_POST(self):
        s = self.server
        fields = dict(urllib.parse.parse_qsl(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode(), keep_blank_values=True))
        path = self.path.split("?")[0]
        s.posts.append((self.path, fields))
        if path == "/asp/GetRandCount.asp":
            self.reply("login-token\n")
        elif path == "/login.cgi":
            s.logins += 1
            good = fields["PassWord"] == base64.b64encode(b"right").decode() and fields["x.X_HW_Token"] == "login-token"
            if not good:
                s.bad += 1
            self.reply("", cookie="Cookie=sid=abc:Language:english:id=1;path=/;HttpOnly" if good else None)
        elif path == R.TOKEN_PAGE:
            self.reply("session-token")
        elif path == "/logout.cgi":
            s.logouts += 1
            self.reply("")
        elif fields.get("x.X_HW_Token") != "session-token":
            self.reply("", 403)
        elif path == "/add.cgi":
            if not s.ignore_changes:
                s.reserved[max(s.reserved, default=0) + 1] = (fields["x.Yiaddr"], fields["x.Chaddr"])
            self.reply("")
        elif path == "/del.cgi":
            if not s.ignore_changes:
                for i in list(s.reserved):
                    if f"{R.RESERVED_TREE}.{i}" in fields:
                        del s.reserved[i]
            self.reply("")
        else:
            self.reply("")


class Session(unittest.TestCase):
    def setUp(self):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeRouter)
        server.bad = server.left = server.logins = server.logouts = 0
        server.posts = []
        server.ignore_changes = False
        server.reserved = {1: ("10.0.0.9", "aa:aa:aa:aa:aa:09")}
        server.devices = [device("10.0.0.4", "aa:aa:aa:aa:aa:03", "plug"), device("10.0.0.9", "aa:aa:aa:aa:aa:09", "box")]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        self.server = server
        self.config = {"host": f"127.0.0.1:{server.server_address[1]}", "user": "root"}

    def run_command(self, run, **options):
        args = argparse.Namespace(json=False, yes=False, **options)
        with R.Router(self.config, "right") as r, contextlib.redirect_stdout(io.StringIO()):
            run(r, args)

    def test_a_refused_login_is_tried_once_and_says_so(self):
        with self.assertRaisesRegex(R.Error, "1 of 3"), R.Router(self.config, "wrong"):
            pass
        self.assertEqual(self.server.logins, 1)

    def test_a_locked_login_is_not_even_tried(self):
        self.server.bad, self.server.left = 3, 60
        with self.assertRaisesRegex(R.Error, "locked"), R.Router(self.config, "right"):
            pass
        self.assertEqual(self.server.logins, 0)

    def test_a_session_logs_out_even_when_a_command_fails(self):
        with self.assertRaises(R.Error):
            self.run_command(R.cmd_reserve, device="nothing", ip=None)
        self.assertEqual(self.server.logouts, 1)

    def test_reserve_keeps_the_address_it_has_by_default(self):
        self.run_command(R.cmd_reserve, device="plug", ip=None)
        self.assertIn(("10.0.0.4", "aa:aa:aa:aa:aa:03"), self.server.reserved.values())

    def test_reserve_refuses_what_the_router_page_refuses(self):
        for name, ip, why in (("box", None, "already has"), ("plug", "10.0.0.9", "already reserved"), ("plug", "192.0.2.1", "isn't on"), ("plug", "nonsense", "isn't an address")):
            with self.assertRaisesRegex(R.Error, why):
                self.run_command(R.cmd_reserve, device=name, ip=ip)
        self.assertEqual(len(self.server.reserved), 1, "nothing was sent")

    def test_unreserve_by_name_address_or_mac(self):
        for query in ("box", "10.0.0.9", "AA:AA:AA:AA:AA:09"):
            self.server.reserved = {1: ("10.0.0.9", "aa:aa:aa:aa:aa:09")}
            self.run_command(R.cmd_unreserve, device=query)
            self.assertEqual(self.server.reserved, {}, query)

    def test_a_change_the_router_ignored_is_an_error(self):
        self.server.ignore_changes = True
        with self.assertRaisesRegex(R.Error, "didn't take it"):
            self.run_command(R.cmd_reserve, device="plug", ip=None)
        with self.assertRaisesRegex(R.Error, "didn't take it"):
            self.run_command(R.cmd_unreserve, device="box")

    def test_a_restart_or_a_setting_needs_an_answer(self):
        for run, options in ((R.cmd_reboot, {}), (R.cmd_set, {"path": "a.b", "settings": ["x=1"]})):
            with self.assertRaisesRegex(R.Error, "-y"):
                self.run_command(run, **options)
        self.assertFalse([p for p, _ in self.server.posts if p.startswith("/set.cgi")])


if __name__ == "__main__":
    unittest.main()
