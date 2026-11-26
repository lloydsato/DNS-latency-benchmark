#!/usr/bin/env python3
"""Tests for dns_speed_test_macos.sh and dns_speed_test_win.ps1.

Run:   python3 tests/test_benchmark.py -v

Needs only the Python standard library. End-to-end tests run the real scripts
against tests/mock_dns.py on 127.0.0.1 / ::1, so nothing touches the internet.

Environment:
  BASH_BIN   bash to test (default: bash on PATH). On macOS CI this is
             /bin/bash, i.e. the bash 3.2 that ships with macOS.
  PWSH_BIN   PowerShell to test (default: pwsh, else powershell).
  SKIP_BASH / SKIP_PS   set to 1 to skip that script's tests.
Tests for a script are skipped when its interpreter (or dig) isn't available.
"""
import ipaddress
import json
import math
import os
import random
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASH_SCRIPT = os.path.join(ROOT, "dns_speed_test_macos.sh")
PS_SCRIPT = os.path.join(ROOT, "dns_speed_test_win.ps1")
MOCK = os.path.join(ROOT, "tests", "mock_dns.py")

BASH = None if os.environ.get("SKIP_BASH") == "1" else (os.environ.get("BASH_BIN") or shutil.which("bash"))
PWSH = None if os.environ.get("SKIP_PS") == "1" else (
    os.environ.get("PWSH_BIN") or shutil.which("pwsh") or shutil.which("powershell"))
DIG = shutil.which("dig")

POPULAR = ["google.com", "amazon.com", "apple.com", "wikipedia.org", "cloudflare.com"]
ZONES = ["google.com", "amazon.com", "microsoft.com", "facebook.com", "wikipedia.org"]
CATS = ["cached", "uncached", "longtail"]


# ------------------------------------------------------------------ helpers

def run(cmd, env=None, timeout=900):
    full_env = dict(os.environ)
    full_env.update(env or {})
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=full_env,
                       timeout=timeout, universal_newlines=True)
    return p.returncode, p.stdout.replace("\r\n", "\n")


def bash_cmd(*args):
    return [BASH, BASH_SCRIPT] + list(args)


def ps_cmd(*args):
    return [PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", PS_SCRIPT] + list(args)


def ps_eval(snippet):
    """Dot-source the script without running it, then run snippet."""
    script = "$env:DNSBENCH_SOURCE_ONLY = '1'; . '%s'; %s" % (PS_SCRIPT.replace("'", "''"), snippet)
    return run([PWSH, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", script])


def bash_eval(snippet):
    """Source the script without running it, then run snippet."""
    return run([BASH, "-c", 'source "$1"; ' + snippet, "_", BASH_SCRIPT], env={"DNSBENCH_SOURCE_ONLY": "1"})


def ipv6_available():
    if not socket.has_ipv6:
        return False
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.bind(("::1", 0))
        s.close()
        return True
    except OSError:
        return False


def free_udp_ports(n):
    socks, ports = [], []
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        socks.append(s)
        ports.append(s.getsockname()[1])
    for s in socks:
        s.close()
    return ports


ROW_RE = re.compile(r"^\s*(\d+|-)(~?)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\d+)%$")
DEAD_RE = re.compile(r"^\s+-\s+(\S+)\s+(\S+)\s+(.+)$")


def num(s):
    return None if s == "n/a" else float(s)


def parse_report(text):
    """Pull the ranked, unreliable and dead tables out of a report."""
    out = {"ranked": [], "unreliable": [], "dead": {}, "text": text}
    section = None
    for line in text.split("\n"):
        if line.startswith("Rank  Server"):
            section = "ranked"
            continue
        if line.startswith("Unreliable ("):
            section = "unreliable"
            continue
        if line.startswith("No usable answer during warm-up"):
            section = "dead"
            continue
        if not line.strip():
            section = None
            continue
        if section in ("ranked", "unreliable"):
            m = ROW_RE.match(line)
            assert m, "unparseable row: %r" % line
            out[section].append({
                "rank": m.group(1), "tied": m.group(2) == "~", "name": m.group(3), "addr": m.group(4),
                "score": num(m.group(5)), "cached": num(m.group(6)), "uncached": num(m.group(7)),
                "longtail": num(m.group(8)), "p95": num(m.group(9)), "jitter": num(m.group(10)),
                "fail": int(m.group(11)),
            })
        elif section == "dead":
            m = DEAD_RE.match(line)
            assert m, "unparseable dead row: %r" % line
            out["dead"][m.group(1)] = m.group(3)
    return out


def results_section(text):
    """The report itself: from the Results banner to the end of the legend."""
    start = text.index("======================================================================\n Results")
    end = text.index("Fail      = lookups that timed out or got no usable answer.") + 60
    return text[start:end]


# ------------------------------------------------- reference implementation
# An independent Python version of the documented scoring rules, used to
# check the numbers both scripts print.

def reference_report(rows, maxfail=10):
    servers, order = {}, []
    tatt, tfail, tsrv = {}, {}, {}
    records = []
    for name, addr, port, test, target, status, ms in rows:
        key = (name, addr, port)
        if key not in servers:
            servers[key] = {"name": name, "addr": addr, "idx": len(order), "wtotal": 0, "wok": 0,
                            "vals": {c: [] for c in CATS}, "all": [], "att": 0, "fails": 0}
            order.append(key)
        s = servers[key]
        ok = status in ("NOERROR", "NXDOMAIN")
        if test == "warmup":
            s["wtotal"] += 1
            s["wok"] += ok
            continue
        t = (test, target)
        records.append((s, test, t, ok, float(ms) if ok else 0.0))
        tatt[t] = tatt.get(t, 0) + 1
        tfail[t] = tfail.get(t, 0) + (not ok)
        tsrv.setdefault(t, set()).add(key)
    broken = {t for t in tatt if len(tsrv[t]) >= 3 and tfail[t] * 2 > tatt[t]}
    for s, test, t, ok, ms in records:
        if t in broken:
            continue
        s["att"] += 1
        if ok:
            s["vals"][test].append(ms)
            s["all"].append(ms)
        else:
            s["fails"] += 1

    def ci(v):
        n = len(v)
        lo = max(1, math.floor(n / 2 - 0.98 * math.sqrt(n)))
        hi = min(n, math.ceil(n / 2 + 1 + 0.98 * math.sqrt(n)))
        return v[lo - 1], v[hi - 1]

    ranked, unreliable, dead = [], [], []
    for key in order:
        s = servers[key]
        s["reach"] = s["wok"] > 0 or s["wtotal"] == 0
        if not s["reach"]:
            dead.append(s)
            continue
        s["has_score"] = all(s["vals"][c] for c in CATS)
        s["med"] = {c: (statistics.median(s["vals"][c]) if s["vals"][c] else None) for c in CATS}
        cv = sorted(s["vals"]["cached"])
        s["jitter"] = (statistics.stdev(cv) if len(cv) >= 2 else 0.0) if cv else None
        if s["has_score"]:
            s["score"] = sum(s["med"][c] for c in CATS) / 3
            bounds = [ci(sorted(s["vals"][c])) for c in CATS]
            s["lo"] = sum(b[0] for b in bounds) / 3
            s["hi"] = sum(b[1] for b in bounds) / 3
        allv = sorted(s["all"])
        s["p95"] = allv[-(-95 * len(allv) // 100) - 1] if allv else None
        s["fail"] = 100.0 * s["fails"] / s["att"] if s["att"] else 0.0
        (ranked if s["has_score"] and s["fail"] <= maxfail else unreliable).append(s)
    ranked.sort(key=lambda s: (s["score"], s["fail"], s["idx"]))
    unreliable.sort(key=lambda s: (s["fail"], not s["has_score"], s["score"] if s["has_score"] else 0, s["idx"]))
    tied = set()
    if ranked:
        tied = {s["name"] for s in ranked[1:] if s["lo"] <= ranked[0]["hi"]}
        if tied:
            tied.add(ranked[0]["name"])
    return {"ranked": ranked, "unreliable": unreliable, "dead": dead, "tied": tied, "broken": broken}


def synthetic_rows(seed):
    """Made-up measurements covering the interesting cases."""
    rnd = random.Random(seed)
    rows = []

    def server(name, addr, cached, uncached, longtail, fail_rate=0.0, warm_ok=True,
               fail_status="TIMEOUT", decimals=False, uncached_status=None):
        port = "53"
        for d in POPULAR[:2]:
            rows.append((name, addr, port, "warmup", d, "NOERROR" if warm_ok else fail_status,
                         str(rnd.randint(5, 50)) if warm_ok else "-"))
        if not warm_ok:
            return
        for r in range(3):
            plan = [("cached", d, cached) for d in POPULAR] + [("uncached", z, uncached) for z in ZONES]
            plan += [("longtail", "lt%d-%d.example" % (r, k), longtail) for k in range(4)]
            plan += [("longtail", "broken.example", longtail)]
            for test, target, (mu, sd) in plan:
                if target == "broken.example" and name != "Fine-Broken":
                    rows.append((name, addr, port, test, target, "SERVFAIL", "3"))
                    continue
                if test == "uncached" and uncached_status:
                    rows.append((name, addr, port, test, target, uncached_status, "4"))
                    continue
                if rnd.random() < fail_rate:
                    rows.append((name, addr, port, test, target, fail_status, "-"))
                    continue
                v = max(0.1, rnd.gauss(mu, sd))
                ms = "%.3f" % v if decimals else str(int(round(v)))
                status = "NXDOMAIN" if test == "uncached" else "NOERROR"
                rows.append((name, addr, port, test, target, status, ms))

    server("Alpha", "192.0.2.1", (10, 2), (50, 10), (25, 5))
    server("Alpha-Twin", "192.0.2.2", (10, 2), (50, 10), (25, 5), decimals=True)
    server("Slow", "192.0.2.3", (60, 5), (200, 30), (120, 20))
    server("Lossy", "192.0.2.4", (12, 2), (55, 10), (30, 5), fail_rate=0.25)
    server("No-Uncached", "192.0.2.5", (12, 2), (55, 10), (30, 5), uncached_status="SERVFAIL")
    server("Dead", "192.0.2.6", (0, 0), (0, 0), (0, 0), warm_ok=False)
    server("Refuser", "192.0.2.7", (0, 0), (0, 0), (0, 0), warm_ok=False, fail_status="REFUSED")
    server("V6-Good", "2001:db8::1", (14, 3), (52, 10), (27, 5), decimals=True)
    server("V6-Dead", "2001:db8::2", (0, 0), (0, 0), (0, 0), warm_ok=False, fail_status="NETERR")
    server("Fine-Broken", "192.0.2.8", (30, 2), (80, 10), (45, 5))
    return rows


def write_raw(path, rows):
    with open(path, "w", newline="\n") as f:
        f.write("server\taddress\tport\ttest\ttarget\tstatus\tms\n")
        for r in rows:
            f.write("\t".join(r) + "\n")


# ------------------------------------------------------------- static tests

def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class StaticChecks(unittest.TestCase):
    def setUp(self):
        self.sh = read(BASH_SCRIPT)
        self.ps = read(PS_SCRIPT)

    def sh_servers(self):
        block = re.search(r"^SERVERS=\(\n(.*?)^\)", self.sh, re.S | re.M).group(1)
        return [" ".join(m.split()) for m in re.findall(r'^\s*"(.+)"\s*$', block, re.M)]

    def ps_servers(self):
        block = re.search(r"^\$Servers = @\(\n(.*?)^\)", self.ps, re.S | re.M).group(1)
        return [" ".join(m.split()) for m in re.findall(r"^\s*'(.+)'\s*$", block, re.M)]

    def test_server_lists_identical(self):
        self.assertGreater(len(self.sh_servers()), 50)
        self.assertEqual(self.sh_servers(), self.ps_servers())

    def test_domain_lists_identical(self):
        for sh_name, ps_name in [("CACHED_DOMAINS", "CachedDomains"), ("UNCACHED_ZONES", "UncachedZones"),
                                 ("LONGTAIL_DOMAINS", "LongtailDomains")]:
            sh = re.search(r"^%s=\((.*?)\)" % sh_name, self.sh, re.S | re.M).group(1).split()
            ps = re.findall(r"'([^']+)'", re.search(r"^\$%s = @\((.*?)\)" % ps_name, self.ps, re.S | re.M).group(1))
            self.assertEqual(sh, ps, sh_name)
        self.assertEqual(re.search(r"^CACHED_DOMAINS=\((.*?)\)", self.sh, re.M).group(1).split(), POPULAR)
        self.assertEqual(re.search(r"^UNCACHED_ZONES=\((.*?)\)", self.sh, re.M).group(1).split(), ZONES)

    def test_server_entries_valid(self):
        names, addrs = set(), set()
        for entry in self.sh_servers():
            name, addr = entry.split()
            ip = ipaddress.ip_address(addr)
            self.assertNotIn(name, names, "duplicate name")
            self.assertNotIn(ip, addrs, "duplicate address")
            names.add(name)
            addrs.add(ip)
            self.assertTrue(ip.is_global, "%s is not a public address" % addr)
            self.assertEqual(name.endswith("-v6"), ip.version == 6, entry)
        # removed: discontinued, DoH/DoT-only, or someone's personal resolver
        for gone in ["194.242.2.2", "194.242.2.3", "193.110.81.0", "185.253.5.0", "80.80.80.80",
                     "80.80.81.81", "80.80.60.60", "2405:201:4018:6235::1"]:
            self.assertNotIn(ipaddress.ip_address(gone), addrs)

    def test_powershell_script_is_ascii(self):
        # Windows PowerShell 5.1 reads BOM-less scripts as ANSI, so non-ASCII
        # characters would be garbled.
        with open(PS_SCRIPT, "rb") as f:
            data = f.read()
        bad = [i for i, b in enumerate(data) if b > 127]
        self.assertEqual(bad, [], "non-ASCII bytes in the .ps1")

    def test_bash_script_avoids_bash4_and_gnu_only_features(self):
        # macOS ships bash 3.2 and BSD tools.
        code = "\n".join(l for l in self.sh.split("\n") if not l.lstrip().startswith("#"))
        forbidden = {
            r"declare\s+-[a-zA-Z]*A|local\s+-[a-zA-Z]*A": "associative arrays (bash 4)",
            r"\bmapfile\b|\breadarray\b": "mapfile/readarray (bash 4)",
            r"\$\{[A-Za-z_][A-Za-z_0-9]*(,,|\^\^|,|\^)\}": "case modification (bash 4)",
            r"\bwait\s+-n\b": "wait -n (bash 4.3)",
            r"\|&": "|& (bash 4)",
            r"\bcoproc\b": "coproc (bash 4)",
            r"EPOCHSECONDS|EPOCHREALTIME": "EPOCH* (bash 5)",
            r"\[\[\s+-v\s": "[[ -v (bash 4.2)",
            r";;&|;&\s*$": "case fallthrough (bash 4)",
            r"&>>": "&>> (bash 4)",
            r"\$\{[^}]*@[QEPAaKUuL]\}": "${var@op} (bash 4.4+)",
            r"\blocal\s+[A-Za-z_][A-Za-z_0-9]*=\(": "local array initialisation",
            r"\bsed\s+(-[a-zA-Z]*\s+)*-i\b": "sed -i (differs on BSD)",
            r"\bshuf\b": "shuf (not on macOS)",
            r"%N": "date %N (not on macOS)",
            r"readlink\s+-f": "readlink -f",
            r"grep\s+-[a-zA-Z]*P": "grep -P",
            r"sort\s+-[a-zA-Z]*R": "sort -R",
            r"xargs\s+(-[a-zA-Z]+\s+)*-r\b": "xargs -r",
            r"stat\s+-c": "stat -c",
            r"head\s+-n\s+-": "head -n -N",
        }
        for pattern, what in forbidden.items():
            self.assertIsNone(re.search(pattern, code, re.M), "bash script uses %s" % what)


# -------------------------------------------------------- function tests

LOCAL = ["192.168.1.1", "10.0.0.1", "172.16.0.1", "172.31.255.255", "100.64.0.1", "100.100.100.100",
         "100.127.255.254", "127.0.0.1", "127.0.0.53", "169.254.10.1", "0.0.0.0", "::1", "::",
         "fe80::1", "fe80::1%en0", "FE80::ABCD", "febf::1", "fec0:0:0:ffff::1", "fd00::1", "fc12:3456::1",
         "::ffff:192.168.1.1"]
PUBLIC = ["8.8.8.8", "1.1.1.1", "172.15.0.1", "172.32.0.1", "100.63.255.255", "100.128.0.1", "192.169.0.1",
          "2606:4700:4700::1111", "2001:4860:4860::8888", "fe7f::1", "2405:201:4018:6235::1", "::ffff:8.8.8.8",
          "fbff::1"]

SCUTIL_FIXTURE = """DNS configuration

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 2405:201:4018:6235::1
  nameserver[2] : fe80::1%en0
  if_index : 15 (en0)
  flags    : Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)

resolver #2
  domain   : corp.example.com
  nameserver[0] : 10.8.0.1
  flags    : Supplemental, Request A records
  reach    : 0x00000003 (Reachable,Transient Connection)
  order    : 102400

resolver #3
  domain   : local
  options  : mdns
  timeout  : 5
  flags    : Request A records, Request AAAA records
  reach    : 0x00000000 (Not Reachable)
  order    : 300000

DNS configuration (for scoped queries)

resolver #1
  search domain[0] : lan
  nameserver[0] : 192.168.1.1
  nameserver[1] : 203.0.113.53
  if_index : 15 (en0)
  flags    : Scoped, Request A records, Request AAAA records
  reach    : 0x00020002 (Reachable,Directly Reachable Address)
"""


@unittest.skipUnless(BASH, "bash not available")
class BashFunctions(unittest.TestCase):
    def test_local_address_filter(self):
        snippet = 'for a in "$@"; do if is_local_address "$a"; then echo "$a yes"; else echo "$a no"; fi; done'
        code, out = run([BASH, "-c", 'source "$1"; shift; ' + snippet, "_", BASH_SCRIPT] + LOCAL + PUBLIC,
                        env={"DNSBENCH_SOURCE_ONLY": "1"})
        self.assertEqual(code, 0, out)
        got = dict(line.rsplit(" ", 1) for line in out.strip().split("\n"))
        for a in LOCAL:
            self.assertEqual(got[a], "yes", a)
        for a in PUBLIC:
            self.assertEqual(got[a], "no", a)

    def test_scutil_parsing(self):
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
            f.write(SCUTIL_FIXTURE)
        try:
            code, out = bash_eval('parse_scutil_dns < "%s"' % f.name)
        finally:
            os.unlink(f.name)
        self.assertEqual(code, 0, out)
        # default resolver only: not the corp VPN domain, mDNS, or the scoped section
        self.assertEqual(out.split(), ["192.168.1.1", "2405:201:4018:6235::1", "fe80::1%en0"])

    def test_bad_arguments(self):
        for args, msg in [(["--rounds", "0"], "--rounds"), (["--jobs", "x"], "--jobs"),
                          (["--timeout"], "needs a value"), (["--bogus"], "unknown option")]:
            code, out = run(bash_cmd(*args))
            self.assertNotEqual(code, 0, args)
            self.assertIn(msg, out)

    def test_help(self):
        code, out = run(bash_cmd("--help"))
        self.assertEqual(code, 0)
        self.assertIn("--ipv4-only", out)


@unittest.skipUnless(PWSH, "PowerShell not available")
class PowerShellFunctions(unittest.TestCase):
    def test_local_address_filter(self):
        arr = ",".join("'%s'" % a for a in LOCAL + PUBLIC)
        code, out = ps_eval("foreach ($a in @(%s)) { '{0} {1}' -f $a, (Test-LocalAddress $a) }" % arr)
        self.assertEqual(code, 0, out)
        got = dict(line.rsplit(" ", 1) for line in out.strip().split("\n"))
        for a in LOCAL:
            self.assertEqual(got[a], "True", a)
        for a in PUBLIC:
            self.assertEqual(got[a], "False", a)

    def test_bad_arguments(self):
        code, out = run(ps_cmd("-Rounds", "0"))
        self.assertNotEqual(code, 0)
        self.assertIn("-Rounds", out)

    def test_help(self):
        code, out = run(ps_cmd("-Help"))
        self.assertEqual(code, 0)
        self.assertIn("-IPv4Only", out)


# -------------------------------------------------------- report tests

class ReportTests(unittest.TestCase):
    """Feed made-up measurements to --analyze and check the numbers."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.rows = synthetic_rows(seed=7)
        cls.raw = os.path.join(cls.tmp, "raw.tsv")
        write_raw(cls.raw, cls.rows)
        cls.ref = reference_report(cls.rows)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, text):
        rep = parse_report(text)
        ref = self.ref
        self.assertEqual([r["name"] for r in rep["ranked"]], [s["name"] for s in ref["ranked"]])
        self.assertEqual([r["name"] for r in rep["unreliable"]], [s["name"] for s in ref["unreliable"]])
        self.assertEqual(sorted(rep["dead"]), sorted(s["name"] for s in ref["dead"]))
        self.assertEqual({r["name"] for r in rep["ranked"] if r["tied"]}, ref["tied"])
        by_name = {s["name"]: s for s in ref["ranked"] + ref["unreliable"]}
        for r in rep["ranked"] + rep["unreliable"]:
            s = by_name[r["name"]]
            if s["has_score"]:
                self.assertAlmostEqual(r["score"], s["score"], delta=0.051, msg=r["name"])
            else:
                self.assertIsNone(r["score"])
            for c in CATS:
                if s["med"][c] is None:
                    self.assertIsNone(r[c])
                else:
                    self.assertAlmostEqual(r[c], s["med"][c], delta=0.051, msg="%s %s" % (r["name"], c))
            self.assertAlmostEqual(r["p95"], s["p95"], delta=0.51, msg=r["name"])
            self.assertAlmostEqual(r["jitter"], s["jitter"], delta=0.051, msg=r["name"])
            self.assertLessEqual(abs(r["fail"] - s["fail"]), 0.5 + 1e-9, r["name"])
        self.assertIn("refused our queries", rep["dead"]["Refuser"])
        self.assertIn("timed out", rep["dead"]["Dead"])
        self.assertIn("network error", rep["dead"]["V6-Dead"])
        self.assertIn("Note: excluded broken.example (longtail test) from scoring", text)
        self.assertEqual(len(ref["broken"]), 1)
        self.assertIn("Fastest: %s" % ref["ranked"][0]["name"], text)

    @unittest.skipUnless(BASH, "bash not available")
    def test_bash_report(self):
        code, out = run(bash_cmd("--analyze", self.raw))
        self.assertEqual(code, 0, out)
        self.check(out)

    @unittest.skipUnless(PWSH, "PowerShell not available")
    def test_powershell_report(self):
        code, out = run(ps_cmd("-Analyze", self.raw))
        self.assertEqual(code, 0, out)
        self.check(out)

    @unittest.skipUnless(BASH and PWSH, "needs both bash and PowerShell")
    def test_both_reports_identical(self):
        for seed in (1, 2, 3):
            path = os.path.join(self.tmp, "raw%d.tsv" % seed)
            write_raw(path, synthetic_rows(seed))
            _, a = run(bash_cmd("--analyze", path))
            _, b = run(ps_cmd("-Analyze", path))
            self.assertEqual(a.strip("\n"), b.strip("\n"), "seed %d" % seed)

    @unittest.skipUnless(BASH and PWSH, "needs both bash and PowerShell")
    def test_no_ipv6_note(self):
        rows = [r for r in self.rows if r[0] != "V6-Good"]
        path = os.path.join(self.tmp, "raw_nov6.tsv")
        write_raw(path, rows)
        for cmd in (bash_cmd("--analyze", path), ps_cmd("-Analyze", path)):
            _, out = run(cmd)
            self.assertIn("the only IPv6 server did not answer", out)
            self.assertNotIn("V6-Dead", out)


def edge_rows():
    """Servers placed exactly on the tie and failure-rate boundaries.

    With 15 values per test the confidence interval runs from the 3rd to the
    13th smallest value. Tie-Leader's values are b..b+14 (b = 10), so its upper
    bound is b+12; Tie-Edge (b = 20) has a lower bound of b+2 = 22 -> exactly
    touching, so tied. Tie-Out (b = 21) misses by 1 ms. Fail-Edge fails exactly
    10% of its lookups (allowed); Fail-Over fails 4 of 30 (13%).
    """
    rows = []

    def server(name, addr, base, rounds=3, fail_each=()):
        rows.append((name, addr, "53", "warmup", "google.com", "NOERROR", "5"))
        offsets = {"cached": 0, "longtail": 20, "uncached": 40}
        k = 0
        for r in range(rounds):
            for i in range(5):
                v = base + r * 5 + i
                for test, off in offsets.items():
                    target = {"cached": POPULAR[i], "uncached": ZONES[i]}.get(test, "lt%d-%d.example" % (r, i))
                    k += 1
                    if k in fail_each:
                        rows.append((name, addr, "53", test, target, "TIMEOUT", "-"))
                    else:
                        rows.append((name, addr, "53", test, target,
                                     "NXDOMAIN" if test == "uncached" else "NOERROR", str(v + off)))

    server("Tie-Out", "192.0.2.3", 21)
    server("Tie-Edge", "192.0.2.2", 20)
    server("Tie-Leader", "192.0.2.1", 10)
    server("Fail-Edge", "192.0.2.4", 40, rounds=2, fail_each=(1, 2, 3))
    server("Fail-Over", "192.0.2.5", 40, rounds=2, fail_each=(1, 2, 3, 4))
    return rows


class EdgeCaseReport(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.raw = os.path.join(cls.tmp, "edge.tsv")
        write_raw(cls.raw, edge_rows())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def check(self, text):
        rep = parse_report(text)
        ranked = {r["name"]: r for r in rep["ranked"]}
        self.assertEqual([r["name"] for r in rep["ranked"]], ["Tie-Leader", "Tie-Edge", "Tie-Out", "Fail-Edge"], text)
        self.assertEqual([r["name"] for r in rep["unreliable"]], ["Fail-Over"], text)
        self.assertEqual({n for n, r in ranked.items() if r["tied"]}, {"Tie-Leader", "Tie-Edge"}, text)
        lead = ranked["Tie-Leader"]
        # medians 17 / 57 / 37, score = their mean
        self.assertEqual((lead["cached"], lead["uncached"], lead["longtail"], lead["score"]), (17.0, 57.0, 37.0, 37.0))
        # nearest-rank p95 of 45 values is the 43rd smallest: 50 + 12
        self.assertEqual(lead["p95"], 62)
        # sample standard deviation of 15 consecutive integers: sqrt(20)
        self.assertEqual(lead["jitter"], 4.5)
        self.assertEqual(ranked["Fail-Edge"]["fail"], 10)
        self.assertIn("~ 1 other server is statistically tied", text)
        ref = reference_report(edge_rows())
        self.assertEqual(ref["tied"], {"Tie-Leader", "Tie-Edge"})

    @unittest.skipUnless(BASH, "bash not available")
    def test_bash(self):
        code, out = run(bash_cmd("--analyze", self.raw))
        self.assertEqual(code, 0, out)
        self.check(out)

    @unittest.skipUnless(PWSH, "PowerShell not available")
    def test_powershell(self):
        code, out = run(ps_cmd("-Analyze", self.raw))
        self.assertEqual(code, 0, out)
        self.check(out)


# ------------------------------------------------------ end-to-end tests

class EndToEnd:
    """Runs a script against the mock resolver. Subclasses set the command.

    The exact statistics are checked by the --analyze tests above; these
    check the plumbing: right test in the right column, right units, right
    status handling, parallel runs, raw file.
    """
    ROUNDS = 2
    DELAYS = {"Fast": {"cached": 10, "longtail": 80, "uncached": 160},
              "Slow": {"cached": 250, "longtail": 320, "uncached": 400}}

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.v6 = ipv6_available()
        ports = free_udp_ports(10)
        # Busy CI machines (macOS especially) add tens of ms to the mock's
        # delays, so the speed groups are far apart.
        fast, slow = cls.DELAYS["Fast"], cls.DELAYS["Slow"]
        cls.servers = [
            ("Fast", "127.0.0.1", {"delays": fast}),
            ("Fast-Twin", "127.0.0.1", {"delays": fast}),
            ("Slow", "127.0.0.1", {"delays": slow}),
            ("Jittery", "127.0.0.1", {"delays": {"cached": 150, "longtail": 220, "uncached": 290}, "jitter": 100}),
            ("Lossy", "127.0.0.1", {"delays": fast, "drop_every": 3}),
            ("Servfail", "127.0.0.1", {"rcode": "SERVFAIL"}),
            ("Refuser", "127.0.0.1", {"rcode": "REFUSED"}),
            ("Closed", "127.0.0.1", {"closed": True}),
            ("Blackhole", "127.0.0.1", {"blackhole": True}),
            ("Fast-v6", "::1", {"delays": fast}),
        ]
        conf = {"popular": POPULAR, "servers": []}
        lines = []
        for (name, addr, extra), port in zip(cls.servers, ports):
            c = {"family": 6 if ":" in addr else 4, "port": port}
            c.update(extra)
            conf["servers"].append(c)
            lines.append("%-12s %-10s %d" % (name, addr, port))
        cls.servers_file = os.path.join(cls.tmp, "servers.txt")
        with open(cls.servers_file, "w") as f:
            f.write("# test servers\n" + "\n".join(lines) + "\n")
        conf_path = os.path.join(cls.tmp, "conf.json")
        with open(conf_path, "w") as f:
            json.dump(conf, f)
        ready = os.path.join(cls.tmp, "ready")
        cls.mock = subprocess.Popen([sys.executable, MOCK, conf_path, ready],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        for _ in range(100):
            if os.path.exists(ready):
                break
            time.sleep(0.1)
        else:
            raise RuntimeError("mock DNS server didn't start")
        cls.raw = os.path.join(cls.tmp, "raw.tsv")
        started = time.time()
        cls.code, cls.out = run(cls.command(cls.servers_file, cls.raw, cls.ROUNDS))
        cls.elapsed = time.time() - started
        cls.rep = parse_report(cls.out) if cls.code == 0 else None

    @classmethod
    def tearDownClass(cls):
        cls.mock.kill()
        cls.mock.wait()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_exit_code(self):
        self.assertEqual(self.code, 0, self.out)

    def test_ranking(self):
        ranked = self.rep["ranked"]
        names = [r["name"] for r in ranked]
        fast_group = {"Fast", "Fast-Twin", "Fast-v6"} if self.v6 else {"Fast", "Fast-Twin"}
        # identically configured servers: any order, all statistically tied
        self.assertEqual(set(names[:len(fast_group)]), fast_group, self.out)
        self.assertTrue(all(r["tied"] for r in ranked[:len(fast_group)]), self.out)
        self.assertEqual(set(names[len(fast_group):]), {"Slow", "Jittery"}, self.out)
        self.assertFalse(any(r["tied"] for r in ranked[len(fast_group):]), self.out)
        if not self.v6:
            self.assertIn("the only IPv6 server did not answer", self.out)
            self.assertNotIn("Fast-v6", self.out)

    def test_medians_match_configured_delays(self):
        rows = {r["name"]: r for r in self.rep["ranked"]}
        for name, delays in self.DELAYS.items():
            r = rows[name]
            for col in CATS:
                # never faster than the mock's delay; the loose upper bound
                # catches unit mix-ups (seconds, microseconds), not noise
                self.assertTrue(delays[col] - 2 <= r[col] <= 2 * delays[col] + 100, (name, col, r))
            self.assertTrue(r["cached"] < r["longtail"] < r["uncached"], (name, r))
            self.assertEqual(r["fail"], 0)
        for col in CATS:
            self.assertLess(rows["Fast"][col], rows["Slow"][col], col)

    def test_jitter(self):
        # Jittery adds 100 ms to every other answer: half its cached lookups
        # take ~150 ms and half ~250 ms, a standard deviation of ~53 ms. Allow
        # for timer noise on busy CI machines, which hits every server.
        rows = {r["name"]: r for r in self.rep["ranked"] + self.rep["unreliable"]}
        self.assertGreater(rows["Jittery"]["jitter"], 35, self.out)
        self.assertGreater(rows["Jittery"]["jitter"], rows["Fast"]["jitter"] + 10, self.out)
        self.assertGreater(rows["Jittery"]["p95"], rows["Jittery"]["score"], self.out)

    def test_lossy_server_is_unreliable(self):
        unrel = {r["name"]: r for r in self.rep["unreliable"]}
        self.assertIn("Lossy", unrel, self.out)
        self.assertTrue(25 <= unrel["Lossy"]["fail"] <= 40, unrel["Lossy"])

    def test_dead_servers(self):
        dead = self.rep["dead"]
        self.assertIn("SERVFAIL", dead["Servfail"])
        self.assertIn("refused our queries", dead["Refuser"])
        self.assertIn("no response (timed out)", dead["Blackhole"])
        # a closed UDP port is reported as refused by most systems, but some
        # just drop the packet
        self.assertRegex(dead["Closed"], r"network error|timed out")

    def test_raw_file(self):
        with open(self.raw) as f:
            lines = [l.rstrip("\r\n").split("\t") for l in f if l.strip()]
        self.assertEqual(lines[0], ["server", "address", "port", "test", "target", "status", "ms"])
        rows = lines[1:]
        per = {}
        for r in rows:
            per.setdefault(r[0], {}).setdefault(r[3], []).append(r)
        for name in ("Fast", "Fast-Twin", "Slow", "Jittery", "Lossy"):
            self.assertEqual(len(per[name]["warmup"]), 2)
            self.assertEqual(sorted(x[4] for x in per[name]["warmup"]), sorted(POPULAR[:2]))
            self.assertEqual(len(per[name]["cached"]), 5 * self.ROUNDS)
            self.assertEqual(len(per[name]["uncached"]), 5 * self.ROUNDS)
            self.assertEqual(len(per[name]["longtail"]), 5 * self.ROUNDS)
            self.assertEqual(sorted(set(x[4] for x in per[name]["uncached"])), sorted(ZONES))
            self.assertEqual(sorted(set(x[4] for x in per[name]["cached"])), sorted(POPULAR))
            self.assertTrue(all(x[5] == "NXDOMAIN" for x in per[name]["uncached"] if x[6] != "-"))
            # long-tail domains differ between rounds
            self.assertEqual(len(set(x[4] for x in per[name]["longtail"])), 5 * self.ROUNDS)
        # unreachable servers only got the warm-up
        for name in ("Servfail", "Blackhole", "Closed", "Refuser"):
            self.assertEqual(set(per[name]), {"warmup"})

    def test_analyze_reproduces_report(self):
        code, out = run(self.command_analyze(self.raw))
        self.assertEqual(code, 0, out)
        self.assertEqual(results_section(out), results_section(self.out))

    def test_runs_in_parallel(self):
        # Sequential worst case is far longer: the blackhole server alone
        # costs 2 timeouts, the lossy one ~10, plus 40+ timed queries per server.
        self.assertLess(self.elapsed, 120, self.out)


@unittest.skipUnless(BASH and DIG, "bash or dig not available")
class BashEndToEnd(EndToEnd, unittest.TestCase):
    @staticmethod
    def command(servers_file, raw, rounds):
        return bash_cmd("--servers", servers_file, "--no-system-dns", "--rounds", str(rounds),
                        "--timeout", "1", "--raw", raw)

    @staticmethod
    def command_analyze(raw):
        return bash_cmd("--analyze", raw)

    def test_ipv4_only(self):
        code, out = run(bash_cmd("--servers", self.servers_file, "--no-system-dns", "--rounds", "1",
                                 "--timeout", "1", "--ipv4-only"))
        self.assertEqual(code, 0, out)
        self.assertIn("(9 IPv4, 0 IPv6)", out)
        self.assertNotIn("Fast-v6", out)


@unittest.skipUnless(PWSH, "PowerShell not available")
class PowerShellEndToEnd(EndToEnd, unittest.TestCase):
    @staticmethod
    def command(servers_file, raw, rounds):
        return ps_cmd("-ServersFile", servers_file, "-NoSystemDns", "-Rounds", str(rounds),
                      "-TimeoutSec", "1", "-RawFile", raw)

    @staticmethod
    def command_analyze(raw):
        return ps_cmd("-Analyze", raw)

    def test_ipv4_only(self):
        code, out = run(ps_cmd("-ServersFile", self.servers_file, "-NoSystemDns", "-Rounds", "1",
                               "-TimeoutSec", "1", "-IPv4Only"))
        self.assertEqual(code, 0, out)
        self.assertIn("(9 IPv4, 0 IPv6)", out)
        self.assertNotIn("Fast-v6", out)


if __name__ == "__main__":
    print("bash: %s | PowerShell: %s | dig: %s" % (BASH, PWSH, DIG))
    unittest.main()
