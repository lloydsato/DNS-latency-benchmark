# DNS Latency Benchmark

Scripts that benchmark about 20 public DNS providers (Cloudflare, Google,
Quad9, OpenDNS, AdGuard, NextDNS, DNS4EU, and more — 108 IPv4 and IPv6
addresses in all) plus your machine's currently configured DNS servers, and
rank them by how fast they actually resolve names from **your** network.

Two versions are included, and they produce the same report:

| Script                    | Platform        | Requirements                                     |
|---------------------------|-----------------|--------------------------------------------------|
| `dns_speed_test_macos.sh` | macOS, Linux    | `bash` 3.2+, `dig` (built into macOS)            |
| `dns_speed_test_win.ps1`  | Windows         | PowerShell 5.1+ (built into Windows 10/11)       |

Neither script requires installing anything extra on macOS or Windows. On
Linux, install `dig` (`dnsutils` / `bind9-dnsutils` / `bind-utils`).

## Why

DNS latency depends heavily on your physical location and your ISP's
peering, so there's no universal "fastest" DNS server — it varies from
network to network. These scripts measure real lookups from your machine
against a wide range of well-known resolvers, so you can decide based on
data instead of guesswork.

## macOS / Linux usage

```bash
git clone https://github.com/lloydsato/DNS-latency-benchmark.git
cd DNS-latency-benchmark
chmod +x dns_speed_test_macos.sh   # only needed if you downloaded a zip
./dns_speed_test_macos.sh
```

## Windows usage

Right-click `dns_speed_test_win.ps1` → **Run with PowerShell**, or from a
PowerShell prompt:

```powershell
powershell -ExecutionPolicy Bypass -File .\dns_speed_test_win.ps1
```

> If PowerShell blocks the script due to execution policy, the command above
> bypasses that for this one run without changing your system-wide policy.

With the default settings a run takes roughly one to three minutes, mostly
depending on how many servers time out.

## Options

| macOS / Linux          | Windows              | Meaning                                                         |
|------------------------|----------------------|-----------------------------------------------------------------|
| `-r`, `--rounds N`     | `-Rounds N`          | rounds of each test per server (default 3)                      |
| `-j`, `--jobs N`       | `-Jobs N`            | servers queried at the same time (default 8; 1 = one at a time) |
| `-t`, `--timeout SEC`  | `-TimeoutSec SEC`    | seconds to wait for each answer (default 2)                     |
| `-4`, `--ipv4-only`    | `-IPv4Only`          | skip IPv6 servers                                               |
| `--no-system-dns`      | `-NoSystemDns`       | don't add this machine's current DNS servers                    |
| `--servers FILE`       | `-ServersFile FILE`  | test the servers in FILE instead of the built-in list           |
| `--raw FILE`           | `-RawFile FILE`      | also save every individual measurement (tab-separated)          |
| `--analyze FILE`       | `-Analyze FILE`      | don't measure; re-analyze a file saved with `--raw`/`-RawFile`  |
| `-h`, `--help`         | `-Help`              | show help                                                       |

A servers file has one server per line — `Name Address [Port]` — and lines
starting with `#` are ignored.

## How it measures

A single "average ping" to each server mostly measures whether the answer
was already in that server's cache. The scripts instead run three kinds of
lookups, so the score reflects what you'd experience day to day:

| Test          | What is looked up                                              | What it shows                                                  |
|---------------|----------------------------------------------------------------|----------------------------------------------------------------|
| **Cached**    | 5 popular domains (`google.com`, `amazon.com`, …)             | the network trip to the server — these are always cached       |
| **Uncached**  | random names such as `dnsbench-3f9a1c0e7b2d.microsoft.com`     | a full lookup the server can't have cached (answer: NXDOMAIN)  |
| **Long-tail** | 5 less popular sites per round, from a list of 40              | everyday lookups that may or may not be cached                 |

The random names are under domains that aren't DNSSEC-signed, so resolvers
can't answer them from cached proof that a name doesn't exist (RFC 8198).

To keep the comparison fair:

- **Warm-up.** Every server first gets two untimed queries, so the first
  measured lookup doesn't pay connection or cache set-up costs. Servers that
  give no usable answer here are skipped and listed with the reason
  (timed out, network error, refused, SERVFAIL).
- **Interleaving.** Each round runs the three tests in a random order, and
  each test visits the servers in a random order, so a brief network hiccup
  is spread across servers instead of hitting one of them.
- **Bounded parallelism.** A few servers (8 by default) are queried at once,
  with each server's own lookups one after another, so servers never compete
  with themselves and your connection isn't flooded.
- **Accurate timing on Windows.** The PowerShell version sends its own DNS
  packets and times only the network round trip, instead of timing
  `Resolve-DnsName`, which includes PowerShell's own overhead. The bash
  version uses the query time reported by `dig`.
- **Your router is skipped.** Private and local addresses (`192.168.x.x`,
  `10.x`, `172.16–31.x`, `100.64/10` CGNAT, `127.x`, link-local, IPv6 ULA /
  link-local / site-local) are left out, because they only measure the hop
  to your router, not the resolver behind it.

## Reading the results

Example (made-up numbers):

```
======================================================================
 DNS Latency Benchmark
 109 servers (59 IPv4, 50 IPv6), 45 timed lookups each
 (3 rounds of: popular domains, random uncached names, long-tail domains)
 8 servers at a time, 2s timeout per lookup
======================================================================
...
======================================================================
 Results (milliseconds, lower is better)
======================================================================
Rank  Server         Address          Score  Cached  Uncached  Long-tail    p95  Jitter  Fail
  1~  Cloudflare     1.1.1.1           19.3    11.0      31.0       16.0     40     1.6    0%
  2~  Cloudflare-2   1.0.0.1           22.3    10.0      39.0       18.0     44     1.4    0%
  3~  Current-DNS-1  203.0.113.1       22.7     4.0      38.0       26.0     48     0.9    0%
  4~  Google         8.8.8.8           24.3    13.0      37.0       23.0     43     1.8    0%
  5~  Control-D      76.76.2.0         31.3    15.0      48.0       31.0     56     1.6    0%
  6~  Quad9          9.9.9.9           33.3    12.0      58.0       30.0     69     1.9    0%
  7   OpenDNS        208.67.222.222    42.7    14.0      79.0       35.0     88     1.7    0%
  8   AdGuard        94.140.14.14      44.0    23.0      70.0       39.0     92     2.0    0%

Unreliable (more than 10% of lookups failed, or a test never succeeded):
  -   Yandex         77.88.8.8        108.5    69.5     145.0      111.0    157     5.5   11%

No usable answer during warm-up (skipped):
  -   Comodo-Secure  8.26.56.26      no response (timed out)

Fastest: Cloudflare (1.1.1.1), score 19.3 ms.
~ 5 other servers are statistically tied with it: their likely score ranges
  overlap, so the gaps between them may just be noise. Choose among the
  tied servers on features (privacy, filtering) rather than speed.
```

- **Score** is the average of the three medians (cached, uncached,
  long-tail). Medians aren't thrown off by a single slow lookup the way an
  average is.
- **p95**: 95% of this server's lookups were this fast or faster — a measure
  of how bad its slow lookups get.
- **Jitter** is the standard deviation of the cached lookups, i.e. how
  steady the network path to the server is.
- **Fail** is the share of lookups that timed out or got no usable answer
  (SERVFAIL, REFUSED, …). NXDOMAIN is a correct answer for the random names.
- **`~` (statistical tie)**: the scripts estimate a likely range for each
  score (from 95% confidence intervals of the medians). Servers whose range
  overlaps the leader's are marked `~`; with this much noise you can't say
  which of them is really faster, so choose among them on features.
- **Unreliable** servers are listed separately instead of ranked: a server
  that answers fast but fails more than 10% of the time isn't a good choice.
- If a whole domain fails on most servers (a site's own DNS is broken), it is
  left out of scoring and the report says so, rather than penalising every
  resolver.
- If none of the IPv6 servers answer, your network probably has no IPv6
  connectivity; they're left out of the report with a note.

### Saving and re-analyzing measurements

`--raw results.tsv` (`-RawFile results.tsv` on Windows) saves every
individual lookup — server, address, port, test, name, status and time — for
your own analysis in a spreadsheet. `--analyze results.tsv` re-prints the
report from such a file without measuring again; files from either script
can be analyzed by either script.

## What's included

The built-in list has 58 IPv4 and 50 IPv6 addresses (primary and secondary
for each service):

- **Cloudflare** — standard, malware-blocking, and family variants (IPv4 + IPv6)
- **Google Public DNS** (IPv4 + IPv6)
- **Quad9** — standard, no-filter, and ECS variants (IPv4 + IPv6)
- **OpenDNS (Cisco)** — standard and FamilyShield (IPv4 + IPv6)
- **Control D** (IPv4 + IPv6)
- **AdGuard DNS** — standard, family, and unfiltered (IPv4 + IPv6)
- **NextDNS** (IPv4 + IPv6)
- **CleanBrowsing** — security, family, and adult filters (IPv4 + IPv6)
- **Comodo Secure DNS**
- **UltraDNS Public** (formerly Verisign Public DNS / Neustar) — standard and
  threat-protection (IPv4 + IPv6)
- **Level3 / Lumen**
- **DNS.Watch**
- **Yandex DNS** — standard, safe, and family (IPv4 + IPv6)
- **Alternate DNS**
- **UncensoredDNS** (IPv4 + IPv6)
- **DNS4EU** — protective and unfiltered (IPv4 + IPv6)
- **Gcore Public DNS** (IPv4 + IPv6)

Plus whatever your machine is currently configured to use (shown as
`Current-DNS-1`, `Current-DNS-2`, …). On macOS, resolvers that only serve a
particular domain (for example a VPN's internal domain) aren't included.

No longer listed: dns0.eu (shut down), Freenom World (discontinued), and
Mullvad DNS (its public service is DNS-over-HTTPS/TLS only, which these
scripts don't test).

DNS infrastructure occasionally changes. If a server is always skipped or
unreliable, check whether the provider has published a new address before
assuming your network is at fault.

## Customizing

Edit these near the top of either script (bash name / PowerShell name):

- **Servers** (`SERVERS` / `$Servers`) — `Name Address` entries; or keep the
  script as is and pass your own list with `--servers` / `-ServersFile`.
- **Popular domains** (`CACHED_DOMAINS` / `$CachedDomains`)
- **Zones for random uncached names** (`UNCACHED_ZONES` / `$UncachedZones`) —
  use domains that aren't DNSSEC-signed.
- **Long-tail domains** (`LONGTAIL_DOMAINS` / `$LongtailDomains`) and how many
  are used per round (`LONGTAIL_PER_ROUND` / `$LongtailPerRound`)
- **Failure threshold** for the unreliable list (`MAX_FAIL_PCT` / `$MaxFailPct`)

Rounds, parallel jobs and timeout are command-line options (see above).

## Interpreting results

- **Small differences (a few ms) rarely matter in practice** — DNS answers
  are cached on your machine too, so this latency only affects the *first*
  request to a name, not every page load. Servers marked `~` are effectively
  equally fast.
- **The Uncached column matters most for browsing new sites**: it's what you
  wait for when nobody has looked a name up recently.
- **Your ISP's own DNS is often fastest** on the Cached test, since it's
  usually the closest resolver on the network path. Public DNS providers can
  still be worth using for privacy, malware filtering, or content filtering,
  even if they're a few ms slower.
- **A high failure rate** usually means a server is blocked, rate-limiting
  you, or poorly peered with your network — worth avoiding regardless of its
  speed.

## Applying your results

Once you've found the fastest option, set it at the **router level**
(Settings → DNS, varies by router) so it applies to every device on your
network — rather than configuring each device individually.

- **macOS:** System Settings → Network → [your connection] → DNS
- **Windows:** Settings → Network & Internet → [your connection] → DNS
  server assignment → Edit → Manual

## Tests

```bash
python3 tests/test_benchmark.py -v
```

The tests use only the Python standard library. They check that both
scripts carry the same server and domain lists, compare both scripts'
reports with an independent Python implementation of the scoring, and run
both scripts end to end against a local mock DNS server
(`tests/mock_dns.py`) with fast, slow, jittery, lossy, failing and silent
servers — no internet access needed. Tests for a script are skipped if its
interpreter isn't installed; set `BASH_BIN` or `PWSH_BIN` to test a specific
`bash` or PowerShell. GitHub Actions runs them on Linux, on macOS with the
system `/bin/bash` 3.2, and on Windows with both PowerShell 5.1 and 7.

## License

MIT — do whatever you'd like with this.
