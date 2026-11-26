#!/usr/bin/env python3
"""A tiny fake DNS resolver for testing the benchmark scripts.

Starts one UDP listener per configured server, each with its own behaviour
(delay per test category, jitter, dropped queries, error responses), so the
scripts can be tested end to end without touching the internet.

Usage: mock_dns.py CONFIG.json READY_FILE
  Writes READY_FILE once every listener is bound, then runs until killed.

Config:
  {
    "popular": ["google.com", ...],        # names answered with the "cached" delay
    "servers": [
      {"family": 4, "port": 25301,
       "delays": {"cached": 10, "longtail": 30, "uncached": 60},   # ms
       "jitter": 0,          # extra delay (ms) on every other answer of each kind
       "drop_every": 0,      # drop every Nth query (after the first `reliable_first`)
       "reliable_first": 2,  # always answer this many queries first (the warm-up)
       "rcode": null,        # e.g. "SERVFAIL" to always fail
       "blackhole": false,   # receive but never answer
       "closed": false}      # don't listen at all
    ]
  }
Names starting with "dnsbench-" get NXDOMAIN after the "uncached" delay;
popular names get an A record after the "cached" delay; anything else gets
an A record after the "longtail" delay.
"""
import json
import socket
import sys
import threading

RCODES = {"NOERROR": 0, "FORMERR": 1, "SERVFAIL": 2, "NXDOMAIN": 3, "REFUSED": 5}


def parse_qname(packet):
    labels, i = [], 12
    while i < len(packet) and packet[i] != 0:
        length = packet[i]
        labels.append(packet[i + 1:i + 1 + length].decode("ascii", "replace"))
        i += 1 + length
    return ".".join(labels).lower(), i + 5  # +1 for the root label, +4 for type/class


def build_response(query, rcode, with_answer):
    _, qend = parse_qname(query)
    flags = bytes([0x80 | (query[2] & 0x79), 0x80 | rcode])  # QR, opcode, RD | RA, rcode
    counts = (b"\x00\x01" + (b"\x00\x01" if with_answer else b"\x00\x00") + b"\x00\x00\x00\x00")
    answer = b""
    if with_answer:
        answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04" + bytes([192, 0, 2, 1])
    return query[:2] + flags + counts + query[12:qend] + answer


class Server:
    def __init__(self, conf, popular):
        self.conf = conf
        self.popular = popular
        self.count = 0
        self.per_category = {}
        self.lock = threading.Lock()
        family = socket.AF_INET6 if conf.get("family") == 6 else socket.AF_INET
        host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
        self.sock = socket.socket(family, socket.SOCK_DGRAM)
        self.sock.bind((host, conf["port"]))

    def serve(self):
        while True:
            try:
                data, addr = self.sock.recvfrom(4096)
            except OSError:
                continue  # e.g. ICMP errors surfacing on Windows
            if len(data) < 17:
                continue
            with self.lock:
                self.count += 1
                n = self.count
            conf = self.conf
            if conf.get("blackhole"):
                continue
            every = conf.get("drop_every", 0)
            if every and n > conf.get("reliable_first", 2) and n % every == 0:
                continue
            name, _ = parse_qname(data)
            if name.startswith("dnsbench-"):
                category, rcode, answer = "uncached", RCODES["NXDOMAIN"], False
            elif name in self.popular:
                category, rcode, answer = "cached", 0, True
            else:
                category, rcode, answer = "longtail", 0, True
            if conf.get("rcode"):
                rcode, answer = RCODES[conf["rcode"]], False
            with self.lock:
                k = self.per_category[category] = self.per_category.get(category, 0) + 1
            # deterministic jitter, so tests don't depend on luck
            delay = conf.get("delays", {}).get(category, 0) + (conf.get("jitter", 0) if k % 2 else 0)
            reply = build_response(data, rcode, answer)
            timer = threading.Timer(delay / 1000.0, self.send, (reply, addr))
            timer.daemon = True
            timer.start()

    def send(self, reply, addr):
        try:
            self.sock.sendto(reply, addr)
        except OSError:
            pass


def main():
    config_path, ready_file = sys.argv[1], sys.argv[2]
    if sys.platform == "win32":
        # Windows timers tick every ~15.6 ms by default, which would make the
        # configured delays very imprecise. Ask for 1 ms while we run.
        import ctypes
        ctypes.windll.winmm.timeBeginPeriod(1)
    with open(config_path) as f:
        config = json.load(f)
    popular = set(name.lower() for name in config.get("popular", []))
    servers = []
    for conf in config["servers"]:
        if conf.get("closed"):
            continue
        try:
            servers.append(Server(conf, popular))
        except OSError as e:
            if conf.get("family") != 6:
                raise
            print("mock_dns: no IPv6 here, skipping port %s (%s)" % (conf["port"], e), file=sys.stderr)
    for server in servers:
        threading.Thread(target=server.serve, daemon=True).start()
    with open(ready_file, "w") as f:
        f.write("ready\n")
    threading.Event().wait()


if __name__ == "__main__":
    main()
