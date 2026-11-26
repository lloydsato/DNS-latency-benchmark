#!/bin/bash
#
# dns_speed_test_macos.sh
# Benchmarks ~100 public DNS resolver addresses (IPv4 and IPv6) plus your
# current DNS servers, and ranks them by typical lookup time.
#
# Runs on the bash 3.2 that ships with macOS (and on newer bash on Linux).
# The only tool it needs is `dig`, which macOS includes.
#
# Usage:
#   chmod +x dns_speed_test_macos.sh
#   ./dns_speed_test_macos.sh             # full run
#   ./dns_speed_test_macos.sh --help      # options
#

# ------------------------------------------------------------------ settings

# Popular domains. Big resolvers nearly always have these cached, so this test
# mostly measures the network round trip between you and the resolver.
CACHED_DOMAINS=(google.com amazon.com apple.com wikipedia.org cloudflare.com)

# Zones for the "uncached" test. Every query asks for a random name that does
# not exist (e.g. dnsbench-1a2b3c4d5e6f.google.com). No resolver can have it
# cached, so it has to ask the zone's own servers, which is what happens on a
# real cache miss. These zones are deliberately not DNSSEC-signed: in signed
# zones, validating resolvers can answer random names from cache (RFC 8198).
UNCACHED_ZONES=(google.com amazon.com microsoft.com facebook.com wikipedia.org)

# Less popular sites (universities, registries, open-source projects). Each
# round uses a different random selection, so a resolver may or may not have
# them cached, like the long tail of real browsing.
LONGTAIL_DOMAINS=(
  ethz.ch uio.no helsinki.fi kuleuven.be uva.nl tuwien.at unimelb.edu.au
  auckland.ac.nz ubc.ca kyoto-u.ac.jp usp.br uct.ac.za unam.mx
  uni-heidelberg.de ku.dk tcd.ie ed.ac.uk nus.edu.sg kaist.ac.kr iitb.ac.in
  cuni.cz uw.edu.pl ietf.org isc.org nlnetlabs.nl sqlite.org curl.se
  postgresql.org openbsd.org gnu.org ripe.net apnic.net lacnic.net
  afrinic.net arin.net w3.org unicode.org abs.gov.au smhi.se knmi.nl
)
LONGTAIL_PER_ROUND=5

ROUNDS=3          # rounds of each test per server
JOBS=8            # servers queried at the same time (1 = one at a time)
TIMEOUT=2         # seconds to wait for each answer
MAX_FAIL_PCT=10   # servers failing more than this % are listed as unreliable

# DNS servers to test: "Name Address" (optionally followed by a port).
# "-2" marks a provider's secondary address; "-v6" marks IPv6 addresses.
SERVERS=(
  # Cloudflare
  "Cloudflare                     1.1.1.1"
  "Cloudflare-2                   1.0.0.1"
  "Cloudflare-Malware-Block       1.1.1.2"
  "Cloudflare-Malware-Block-2     1.0.0.2"
  "Cloudflare-Family              1.1.1.3"
  "Cloudflare-Family-2            1.0.0.3"
  "Cloudflare-v6                  2606:4700:4700::1111"
  "Cloudflare-2-v6                2606:4700:4700::1001"
  "Cloudflare-Malware-Block-v6    2606:4700:4700::1112"
  "Cloudflare-Malware-Block-2-v6  2606:4700:4700::1002"
  "Cloudflare-Family-v6           2606:4700:4700::1113"
  "Cloudflare-Family-2-v6         2606:4700:4700::1003"
  # Google
  "Google                         8.8.8.8"
  "Google-2                       8.8.4.4"
  "Google-v6                      2001:4860:4860::8888"
  "Google-2-v6                    2001:4860:4860::8844"
  # Quad9
  "Quad9                          9.9.9.9"
  "Quad9-2                        149.112.112.112"
  "Quad9-No-Filter                9.9.9.10"
  "Quad9-No-Filter-2              149.112.112.10"
  "Quad9-ECS                      9.9.9.11"
  "Quad9-ECS-2                    149.112.112.11"
  "Quad9-v6                       2620:fe::fe"
  "Quad9-2-v6                     2620:fe::9"
  "Quad9-No-Filter-v6             2620:fe::10"
  "Quad9-No-Filter-2-v6           2620:fe::fe:10"
  "Quad9-ECS-v6                   2620:fe::11"
  "Quad9-ECS-2-v6                 2620:fe::fe:11"
  # OpenDNS (Cisco)
  "OpenDNS                        208.67.222.222"
  "OpenDNS-2                      208.67.220.220"
  "OpenDNS-FamilyShield           208.67.222.123"
  "OpenDNS-FamilyShield-2         208.67.220.123"
  "OpenDNS-v6                     2620:119:35::35"
  "OpenDNS-2-v6                   2620:119:53::53"
  "OpenDNS-FamilyShield-v6        2620:119:35::123"
  "OpenDNS-FamilyShield-2-v6      2620:119:53::123"
  # Control D (free, unfiltered)
  "Control-D                      76.76.2.0"
  "Control-D-2                    76.76.10.0"
  "Control-D-v6                   2606:1a40::"
  "Control-D-2-v6                 2606:1a40:1::"
  # AdGuard
  "AdGuard                        94.140.14.14"
  "AdGuard-2                      94.140.15.15"
  "AdGuard-Family                 94.140.14.15"
  "AdGuard-Family-2               94.140.15.16"
  "AdGuard-Unfiltered             94.140.14.140"
  "AdGuard-Unfiltered-2           94.140.14.141"
  "AdGuard-v6                     2a10:50c0::ad1:ff"
  "AdGuard-2-v6                   2a10:50c0::ad2:ff"
  "AdGuard-Family-v6              2a10:50c0::bad1:ff"
  "AdGuard-Family-2-v6            2a10:50c0::bad2:ff"
  "AdGuard-Unfiltered-v6          2a10:50c0::1:ff"
  "AdGuard-Unfiltered-2-v6        2a10:50c0::2:ff"
  # NextDNS (anycast, no profile)
  "NextDNS                        45.90.28.0"
  "NextDNS-2                      45.90.30.0"
  "NextDNS-v6                     2a07:a8c0::"
  "NextDNS-2-v6                   2a07:a8c1::"
  # CleanBrowsing
  "CleanBrowsing-Security         185.228.168.9"
  "CleanBrowsing-Security-2       185.228.169.9"
  "CleanBrowsing-Family           185.228.168.168"
  "CleanBrowsing-Family-2         185.228.169.168"
  "CleanBrowsing-Adult            185.228.168.10"
  "CleanBrowsing-Adult-2          185.228.169.11"
  "CleanBrowsing-Security-v6      2a0d:2a00:1::2"
  "CleanBrowsing-Security-2-v6    2a0d:2a00:2::2"
  "CleanBrowsing-Family-v6        2a0d:2a00:1::"
  "CleanBrowsing-Family-2-v6      2a0d:2a00:2::"
  "CleanBrowsing-Adult-v6         2a0d:2a00:1::1"
  "CleanBrowsing-Adult-2-v6       2a0d:2a00:2::1"
  # Comodo Secure DNS
  "Comodo-Secure                  8.26.56.26"
  "Comodo-Secure-2                8.20.247.20"
  # UltraDNS Public (Vercara/DigiCert; formerly Verisign and Neustar)
  "UltraDNS                       64.6.64.6"
  "UltraDNS-2                     64.6.65.6"
  "UltraDNS-Threat                156.154.70.2"
  "UltraDNS-Threat-2              156.154.71.2"
  "UltraDNS-v6                    2620:74:1b::1:1"
  "UltraDNS-2-v6                  2620:74:1c::2:2"
  "UltraDNS-Threat-v6             2610:a1:1018::2"
  "UltraDNS-Threat-2-v6           2610:a1:1019::2"
  # Level3 / Lumen (long-standing, though never an official public service)
  "Level3                         4.2.2.1"
  "Level3-2                       4.2.2.2"
  # DNS.Watch
  "DNS-Watch                      84.200.69.80"
  "DNS-Watch-2                    84.200.70.40"
  # Yandex
  "Yandex                         77.88.8.8"
  "Yandex-2                       77.88.8.1"
  "Yandex-Safe                    77.88.8.88"
  "Yandex-Family                  77.88.8.7"
  "Yandex-v6                      2a02:6b8::feed:0ff"
  "Yandex-2-v6                    2a02:6b8:0:1::feed:0ff"
  "Yandex-Safe-v6                 2a02:6b8::feed:bad"
  "Yandex-Family-v6               2a02:6b8::feed:a11"
  # Alternate DNS
  "Alternate-DNS                  76.76.19.19"
  "Alternate-DNS-2                76.223.122.150"
  # UncensoredDNS
  "UncensoredDNS                  91.239.100.100"
  "UncensoredDNS-2                89.233.43.71"
  "UncensoredDNS-v6               2001:67c:28a4::"
  "UncensoredDNS-2-v6             2a01:3a0:53:53::"
  # DNS4EU (EU-backed public resolver)
  "DNS4EU-Protective              86.54.11.1"
  "DNS4EU-Protective-2            86.54.11.201"
  "DNS4EU-Unfiltered              86.54.11.100"
  "DNS4EU-Unfiltered-2            86.54.11.200"
  "DNS4EU-Protective-v6           2a13:1001::86:54:11:1"
  "DNS4EU-Protective-2-v6         2a13:1001::86:54:11:201"
  "DNS4EU-Unfiltered-v6           2a13:1001::86:54:11:100"
  "DNS4EU-Unfiltered-2-v6         2a13:1001::86:54:11:200"
  # Gcore
  "Gcore                          95.85.95.85"
  "Gcore-2                        2.56.220.2"
  "Gcore-v6                       2a03:90c0:999d::1"
  "Gcore-2-v6                     2a03:90c0:9992::1"
)

# ---------------------------------------------------------------- internals

export LC_ALL=C        # consistent number formatting and sorting
TAB=$(printf '\t')
IPV4_ONLY=0
USE_SYSTEM_DNS=1
SERVERS_FILE=
RAW_OUT=
ANALYZE_FILE=

usage() {
  cat <<'EOF'
Usage: dns_speed_test_macos.sh [options]

  -r, --rounds N       rounds of each test per server (default 3)
  -j, --jobs N         servers to query at the same time (default 8;
                       1 = one at a time)
  -t, --timeout SEC    seconds to wait for each answer (default 2)
  -4, --ipv4-only      skip IPv6 servers
      --no-system-dns  don't add this machine's current DNS servers
      --servers FILE   test the servers listed in FILE instead of the
                       built-in list (one per line: Name Address [Port];
                       lines starting with # are ignored)
      --raw FILE       also save every individual measurement to FILE
                       (tab-separated)
      --analyze FILE   don't measure anything; re-analyze a file saved
                       earlier with --raw
  -h, --help           show this help
EOF
}

die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

is_uint() { case $1 in '' | *[!0-9]*) return 1 ;; esac; return 0; }

parse_args() {
  while [ $# -gt 0 ]; do
    case $1 in
      -h | --help) usage; exit 0 ;;
      -4 | --ipv4-only) IPV4_ONLY=1; shift; continue ;;
      --no-system-dns) USE_SYSTEM_DNS=0; shift; continue ;;
      -r | --rounds | -j | --jobs | -t | --timeout | --servers | --raw | --analyze)
        [ $# -ge 2 ] || die "$1 needs a value" ;;
      *) die "unknown option: $1 (try --help)" ;;
    esac
    case $1 in
      -r | --rounds) ROUNDS=$2 ;;
      -j | --jobs) JOBS=$2 ;;
      -t | --timeout) TIMEOUT=$2 ;;
      --servers) SERVERS_FILE=$2 ;;
      --raw) RAW_OUT=$2 ;;
      --analyze) ANALYZE_FILE=$2 ;;
    esac
    shift 2
  done
  is_positive "$ROUNDS" || die "--rounds must be a whole number of at least 1"
  is_positive "$JOBS" || die "--jobs must be a whole number of at least 1"
  is_positive "$TIMEOUT" || die "--timeout must be a whole number of seconds (at least 1)"
}

is_positive() {
  if is_uint "$1" && [ "$1" -ge 1 ]; then return 0; fi
  return 1
}

# True for addresses that only reach your own machine, router or LAN
# (private, loopback, link-local, CGNAT, unique-local, site-local). Timing
# those measures the hop to the router, not real upstream DNS.
is_local_address() {
  local a re
  a=$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')
  a=${a%%%*}                                   # drop a zone index like %en0
  case $a in ::ffff:*.*) a=${a#::ffff:} ;; esac  # IPv4-mapped IPv6
  for re in '^10\.' '^127\.' '^0\.' '^169\.254\.' '^192\.168\.' \
            '^172\.(1[6-9]|2[0-9]|3[01])\.' \
            '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.' \
            '^::1?$' '^fe[89ab][0-9a-f]:' '^fe[c-f][0-9a-f]:' '^f[cd][0-9a-f][0-9a-f]:'; do
    [[ $a =~ $re ]] && return 0
  done
  return 1
}

# Reads `scutil --dns` output and prints the nameservers of the default
# resolvers only: not the per-domain ones (VPN split DNS, mDNS for .local)
# and not the "for scoped queries" section, which repeats the same servers.
parse_scutil_dns() {
  awk '
    function flush(   i) {
      if (inblock && !per_domain) for (i = 1; i <= n; i++) print ns[i]
      inblock = 0; per_domain = 0; n = 0
    }
    /^DNS configuration \(for scoped/ { flush(); finished = 1 }
    finished { next }
    /^resolver #/ { flush(); inblock = 1; next }
    /^[ \t]*domain[ \t]*:/ { per_domain = 1 }
    /^[ \t]*nameserver\[[0-9]+\][ \t]*:/ {
      v = $0; sub(/^[^:]*:[ \t]*/, "", v); ns[++n] = v
    }
    END { flush() }'
}

detect_system_dns() {
  if command -v scutil >/dev/null 2>&1; then
    scutil --dns 2>/dev/null | parse_scutil_dns
  elif [ -r /etc/resolv.conf ]; then
    awk '$1 == "nameserver" { print $2 }' /etc/resolv.conf
  fi | awk '!seen[$0]++'
}

# Prints "STATUS MS" for one A query, e.g. "NOERROR 23", "NXDOMAIN 41",
# "SERVFAIL 12", "TIMEOUT -" or "NETERR -". MS is dig's own measurement of
# the time between sending the query and receiving the answer.
dns_query() {
  dig @"$1" -p "$2" "$3" A +tries=1 +time="$TIMEOUT" +noall +comments +stats 2>&1 |
    awk '
      /status:/ { for (i = 1; i <= NF; i++) if ($i == "status:") { s = $(i + 1); sub(/,.*/, "", s) } }
      /Query time:/ { t = $4; if ($5 ~ /usec/) t = t / 1000 }
      /timed out/ { timed_out = 1 }
      END {
        if (s == "") print (timed_out ? "TIMEOUT" : "NETERR"), "-"
        else print s, (t == "" ? "-" : t)
      }'
}

rand_label() { printf '%04x%04x%04x' "$RANDOM" "$RANDOM" "$RANDOM"; }

# One server's share of a pass: query each name in turn, append the results
# to that server's own file. Runs in parallel with other servers via xargs.
run_unit() {
  [ $# -ge 5 ] || return 0
  local idx=$1 addr=$2 port=$3 cat=$4 name qname res
  shift 4
  for name in "$@"; do
    qname=$name
    [ "$cat" = uncached ] && qname="dnsbench-$(rand_label).$name"
    res=$(dns_query "$addr" "$port" "$qname")
    printf '%s\t%s\t%s\t%s\n' "$cat" "$name" "${res% *}" "${res#* }" >> "$RAW_DIR/$idx"
  done
  return 0
}

shuffle_lines() {
  awk -v seed="$RANDOM$RANDOM" 'BEGIN { srand(seed) } { printf "%.12f\t%s\n", rand(), $0 }' |
    sort -n | cut -f 2-
}

# Runs one pass: every active server, in random order, at most $JOBS at once.
# Each pass covers all servers, so a brief network hiccup affects every
# server a little instead of one server a lot.
run_pass() {
  local label=$1 cat=$2 start=$SECONDS
  shift 2
  printf '  %-46s' "$label"
  if [ -s "$ACTIVE_FILE" ]; then
    shuffle_lines < "$ACTIVE_FILE" | while IFS=$TAB read -r idx addr port; do
      printf '%s %s %s %s %s\n' "$idx" "$addr" "$port" "$cat" "$*"
    done | xargs -L 1 -P "$JOBS" "$BASH" -c 'run_unit "$@"' _
  fi
  printf 'done (%ss)\n' $((SECONDS - start))
}

add_server() { # name address port
  printf '%s\t%s\t%s\n' "$1" "$2" "${3:-53}" >> "$SERVERS_TSV"
}

add_server_line() {
  local name addr port
  read -r name addr port _ <<EOF
$1
EOF
  [ -n "$name" ] || return 0
  case $addr in *.* | *:*) ;; *) die "bad server entry (expected: Name Address [Port]): $1" ;; esac
  [ -z "$port" ] || is_uint "$port" || die "bad port in server entry: $1"
  if [ "$IPV4_ONLY" = 1 ]; then case $addr in *:*) return 0 ;; esac; fi
  add_server "$name" "$addr" "$port"
}

load_servers() {
  local entry line ip existing i=1
  : > "$SERVERS_TSV"
  if [ -n "$SERVERS_FILE" ]; then
    [ -r "$SERVERS_FILE" ] || die "can't read $SERVERS_FILE"
    while IFS= read -r line || [ -n "$line" ]; do
      add_server_line "${line%%#*}"
    done < "$SERVERS_FILE"
  else
    for entry in "${SERVERS[@]}"; do add_server_line "$entry"; done
  fi

  [ "$USE_SYSTEM_DNS" = 1 ] || return 0
  for ip in $(detect_system_dns); do
    if is_local_address "$ip"; then
      printf 'Note: skipping %s, your current DNS. It is a local/router address, so it\n' "$ip"
      printf '      would only measure the hop to your router, not real upstream DNS.\n'
      continue
    fi
    case $ip in *:*) [ "$IPV4_ONLY" = 1 ] && continue ;; esac
    existing=$(awk -F'\t' -v a="$ip" 'tolower($2) == tolower(a) && $3 == 53 { print $1; exit }' "$SERVERS_TSV")
    if [ -n "$existing" ]; then
      printf 'Note: your current DNS %s is already in the list as %s.\n' "$ip" "$existing"
      continue
    fi
    add_server "Current-DNS-$i" "$ip" 53
    i=$((i + 1))
  done
}

measure() {
  command -v dig >/dev/null 2>&1 || die "dig not found (it ships with macOS; on Linux install dnsutils or bind-utils)"

  WORK=$(mktemp -d "${TMPDIR:-/tmp}/dnsbench.XXXXXX") || die "can't create a temporary directory"
  trap 'rm -rf "$WORK"' EXIT
  trap 'exit 130' INT TERM
  RAW_DIR=$WORK/raw
  SERVERS_TSV=$WORK/servers.tsv
  ACTIVE_FILE=$WORK/active.tsv
  mkdir "$RAW_DIR" || die "can't create $RAW_DIR"
  export TIMEOUT RAW_DIR
  export -f run_unit dns_query rand_label

  load_servers
  local total n6 n4
  total=$(awk 'END { print NR }' "$SERVERS_TSV")
  [ "$total" -gt 0 ] || die "no servers to test"
  n6=$(awk -F'\t' '$2 ~ /:/' "$SERVERS_TSV" | awk 'END { print NR }')
  n4=$((total - n6))
  local per_round=$(( ${#CACHED_DOMAINS[@]} + ${#UNCACHED_ZONES[@]} + LONGTAIL_PER_ROUND ))

  echo ""
  echo "======================================================================"
  echo " DNS Latency Benchmark"
  echo " $total servers ($n4 IPv4, $n6 IPv6), $((per_round * ROUNDS)) timed lookups each"
  local rword=rounds
  if [ "$ROUNDS" -eq 1 ]; then rword=round; fi
  echo " ($ROUNDS $rword of: popular domains, random uncached names, long-tail domains)"
  echo " $JOBS servers at a time, ${TIMEOUT}s timeout per lookup"
  echo "======================================================================"
  echo ""

  # Every server gets an index; its measurements go to $RAW_DIR/<index>.
  awk -F'\t' -v OFS='\t' '{ print NR, $2, $3 }' "$SERVERS_TSV" > "$ACTIVE_FILE"

  # Warm-up: two untimed queries per server. They prime ARP/NAT/route state
  # and tell us which servers answer at all; the rest are skipped afterwards.
  run_pass "Warm-up (not scored)" warmup "${CACHED_DOMAINS[0]}" "${CACHED_DOMAINS[1]}"
  local idx addr port
  : > "$ACTIVE_FILE.new"
  while IFS=$TAB read -r idx addr port; do
    if [ -f "$RAW_DIR/$idx" ] &&
       awk -F'\t' '$1 == "warmup" && ($3 == "NOERROR" || $3 == "NXDOMAIN") { ok = 1 } END { exit !ok }' "$RAW_DIR/$idx"; then
      printf '%s\t%s\t%s\n' "$idx" "$addr" "$port" >> "$ACTIVE_FILE.new"
    fi
  done < "$ACTIVE_FILE"
  mv "$ACTIVE_FILE.new" "$ACTIVE_FILE"
  printf '  %s of %s servers answered.\n' "$(awk 'END { print NR }' "$ACTIVE_FILE")" "$total"

  # A fresh random selection of long-tail domains for every round.
  local lt_pool lt_count d
  lt_pool=()
  while IFS= read -r d; do lt_pool[${#lt_pool[@]}]=$d; done <<EOF
$(printf '%s\n' "${LONGTAIL_DOMAINS[@]}" | shuffle_lines)
EOF
  lt_count=${#lt_pool[@]}

  local r cat k lt_names
  lt_names=()
  for ((r = 1; r <= ROUNDS; r++)); do
    for cat in $(printf '%s\n' cached uncached longtail | shuffle_lines); do
      case $cat in
        cached)
          run_pass "Round $r/$ROUNDS: popular domains (cached)" cached "${CACHED_DOMAINS[@]}" ;;
        uncached)
          run_pass "Round $r/$ROUNDS: random names (uncached)" uncached "${UNCACHED_ZONES[@]}" ;;
        longtail)
          lt_names=()
          for ((k = 0; k < LONGTAIL_PER_ROUND; k++)); do
            lt_names[k]=${lt_pool[$(( ((r - 1) * LONGTAIL_PER_ROUND + k) % lt_count ))]}
          done
          run_pass "Round $r/$ROUNDS: less popular domains (long tail)" longtail "${lt_names[@]}" ;;
      esac
    done
  done

  # Combine everything into one table: server, address, port, test, target,
  # status, ms.
  RAW_FILE=$WORK/raw.tsv
  printf 'server\taddress\tport\ttest\ttarget\tstatus\tms\n' > "$RAW_FILE"
  local name
  idx=0
  while IFS=$TAB read -r name addr port; do
    idx=$((idx + 1))
    [ -f "$RAW_DIR/$idx" ] || continue
    awk -v p="$name$TAB$addr$TAB$port$TAB" '{ print p $0 }' "$RAW_DIR/$idx" >> "$RAW_FILE"
  done < "$SERVERS_TSV"

  if [ -n "$RAW_OUT" ]; then
    cp "$RAW_FILE" "$RAW_OUT" || die "can't write $RAW_OUT"
  fi
  report "$RAW_FILE"
  [ -z "$RAW_OUT" ] || printf '\nEvery measurement was saved to %s\n' "$RAW_OUT"
  echo ""
  echo "Tip: run this a few times (e.g. morning and evening), since results"
  echo "vary with network conditions and time of day."
}

# Turns raw measurements into the ranked report. The PowerShell version
# implements exactly the same rules; tests check that both agree.
#
#   Score     average of the median Cached, Uncached and Long-tail times
#   likely range of the score: average of each median's ~95% confidence
#             bounds (order statistics); two servers whose ranges overlap
#             are reported as tied
#   p95       nearest-rank 95th percentile of all successful lookups
#   Jitter    standard deviation of the cached lookups
#   Fail      share of lookups with no usable answer (timeouts, SERVFAIL,
#             REFUSED...); NOERROR and NXDOMAIN both count as answers
#
# Servers above MAX_FAIL_PCT are listed as unreliable instead of ranked. A
# domain that fails on most servers is a problem with that domain, not the
# resolvers, so it's excluded from scoring.
report() {
  awk -F'\t' -v maxfail="$MAX_FAIL_PCT" '
    function sortn(a, n,   i, j, v) {
      for (i = 2; i <= n; i++) { v = a[i]; for (j = i - 1; j >= 1 && a[j] > v; j--) a[j + 1] = a[j]; a[j + 1] = v }
    }
    function median(a, n) { return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2 }
    function ci_lo(a, n,   k) { k = int(n / 2 - 0.98 * sqrt(n)); if (k < 1) k = 1; return a[k] }
    function ci_hi(a, n,   x, k) { x = n / 2 + 1 + 0.98 * sqrt(n); k = int(x); if (k < x) k++; if (k > n) k = n; return a[k] }
    function stdev(a, n,   i, m, ss) {
      if (n < 2) return 0
      m = 0; for (i = 1; i <= n; i++) m += a[i]; m /= n
      ss = 0; for (i = 1; i <= n; i++) ss += (a[i] - m) * (a[i] - m)
      return sqrt(ss / (n - 1))
    }
    function rnd(x, d,   m) { m = (d == 0) ? 1 : 10 ^ d; return int(x * m + 0.5) / m }
    function num(x, d) { return (x == "") ? "n/a" : sprintf("%." d "f", rnd(x, d)) }
    # order for ranked servers: score, then failure rate, then list order
    function rank_before(a, b) {
      if (score[a] != score[b]) return score[a] < score[b]
      if (failpct[a] != failpct[b]) return failpct[a] < failpct[b]
      return a < b
    }
    # order for unreliable servers: failure rate, then score (none = last)
    function unrel_before(a, b) {
      if (failpct[a] != failpct[b]) return failpct[a] < failpct[b]
      if (has_score[a] != has_score[b]) return has_score[a] > has_score[b]
      if (has_score[a] && score[a] != score[b]) return score[a] < score[b]
      return a < b
    }
    function sort_by(list, n, how,   i, j, v, before) {
      for (i = 2; i <= n; i++) {
        v = list[i]
        for (j = i - 1; j >= 1; j--) {
          before = (how == "rank") ? rank_before(v, list[j]) : unrel_before(v, list[j])
          if (!before) break
          list[j + 1] = list[j]
        }
        list[j + 1] = v
      }
    }
    function dead_reason(s) {
      if (wst[s, "TIMEOUT"]) return "no response (timed out)"
      if (wst[s, "NETERR"]) return "network error (unreachable or refused)"
      if (wst[s, "REFUSED"]) return "refused our queries"
      if (wst[s, "SERVFAIL"]) return "answered SERVFAIL (server failure)"
      return "no usable answer (" wlast[s] ")"
    }

    FNR == 1 && $1 == "server" && $4 == "test" { next }
    NF < 7 { next }
    {
      key = $1 SUBSEP $2 SUBSEP $3
      if (!(key in sid)) { sid[key] = ++ns; sname[ns] = $1; saddr[ns] = $2 }
      s = sid[key]; cat = $4; st = $6
      ok = (st == "NOERROR" || st == "NXDOMAIN")
      if (cat == "warmup") {
        wtotal[s]++
        if (ok) wok[s]++; else { wst[s, st] = 1; wlast[s] = st }
        next
      }
      if (cat != "cached" && cat != "uncached" && cat != "longtail") next
      t = cat SUBSEP $5
      nrec++; rs[nrec] = s; rc[nrec] = cat; rt[nrec] = t; rok[nrec] = ok; rms[nrec] = $7 + 0
      tatt[t]++
      if (!ok) tfail[t]++
      if (!((t, s) in tsrv)) { tsrv[t, s] = 1; tnsrv[t]++ }
    }

    END {
      cats[1] = "cached"; cats[2] = "uncached"; cats[3] = "longtail"

      # targets that failed most of the time, across at least 3 servers
      nb = 0
      for (t in tatt) if (tnsrv[t] >= 3 && tfail[t] * 2 > tatt[t]) { broken[t] = 1; blist[++nb] = t }
      for (i = 2; i <= nb; i++) { v = blist[i]; for (j = i - 1; j >= 1 && blist[j] > v; j--) blist[j + 1] = blist[j]; blist[j + 1] = v }

      for (i = 1; i <= nrec; i++) {
        if (rt[i] in broken) continue
        s = rs[i]; att[s]++
        if (rok[i]) {
          k = s SUBSEP rc[i]; cnt[k]++; val[k, cnt[k]] = rms[i]
          acnt[s]++; aval[s, acnt[s]] = rms[i]
        } else fails[s]++
      }

      nr = 0; nu = 0; nd = 0; n6 = 0; n6ok = 0
      for (s = 1; s <= ns; s++) {
        is6[s] = (saddr[s] ~ /:/)
        reach[s] = (wok[s] > 0 || wtotal[s] == 0)
        if (is6[s]) { n6++; if (reach[s]) n6ok++ }
        if (!reach[s]) { dead[++nd] = s; continue }

        has_score[s] = 1; ssum = 0; slo = 0; shi = 0; jit[s] = ""
        for (c = 1; c <= 3; c++) {
          k = s SUBSEP cats[c]; n = cnt[k] + 0
          if (n == 0) { has_score[s] = 0; med[s, c] = ""; continue }
          for (i = 1; i <= n; i++) tmp[i] = val[k, i]
          sortn(tmp, n)
          med[s, c] = median(tmp, n)
          ssum += med[s, c]; slo += ci_lo(tmp, n); shi += ci_hi(tmp, n)
          if (c == 1) jit[s] = stdev(tmp, n)
        }
        if (has_score[s]) { score[s] = ssum / 3; scorelo[s] = slo / 3; scorehi[s] = shi / 3 }

        n = acnt[s] + 0; p95[s] = ""
        if (n > 0) {
          for (i = 1; i <= n; i++) tmp[i] = aval[s, i]
          sortn(tmp, n)
          p95[s] = tmp[int((95 * n + 99) / 100)]
        }
        failpct[s] = att[s] ? 100 * (fails[s] + 0) / att[s] : 0

        if (has_score[s] && failpct[s] <= maxfail) rel[++nr] = s; else unrel[++nu] = s
      }
      sort_by(rel, nr, "rank")
      sort_by(unrel, nu, "unrel")

      ntied = 0
      if (nr > 0) {
        lead = rel[1]
        for (i = 2; i <= nr; i++) if (scorelo[rel[i]] <= scorehi[lead]) { tied[rel[i]] = 1; ntied++ }
        if (ntied) tied[lead] = 1
      }
      skip6 = (n6 > 0 && n6ok == 0)

      wn = length("Server"); wa = length("Address")
      for (s = 1; s <= ns; s++) {
        if (!reach[s] && skip6 && is6[s]) continue
        if (length(sname[s]) > wn) wn = length(sname[s])
        if (length(saddr[s]) > wa) wa = length(saddr[s])
      }
      row = "%-6s%-" wn "s  %-" wa "s  %6s  %6s  %8s  %9s  %5s  %6s  %4s\n"
      line = "======================================================================"

      print ""
      print line
      print " Results (milliseconds, lower is better)"
      print line
      if (nr == 0) print "No server answered reliably enough to rank."
      else {
        printf row, "Rank", "Server", "Address", "Score", "Cached", "Uncached", "Long-tail", "p95", "Jitter", "Fail"
        for (i = 1; i <= nr; i++) {
          s = rel[i]
          printf row, sprintf("%3d%s", i, tied[s] ? "~" : " "), sname[s], saddr[s], num(score[s], 1), \
            num(med[s, 1], 1), num(med[s, 2], 1), num(med[s, 3], 1), num(p95[s], 0), num(jit[s], 1), \
            sprintf("%d%%", rnd(failpct[s], 0))
        }
      }

      if (nu > 0) {
        print ""
        printf "Unreliable (more than %d%% of lookups failed, or a test never succeeded):\n", maxfail
        for (i = 1; i <= nu; i++) {
          s = unrel[i]
          printf row, "  -", sname[s], saddr[s], num(has_score[s] ? score[s] : "", 1), \
            num(med[s, 1], 1), num(med[s, 2], 1), num(med[s, 3], 1), num(p95[s], 0), num(jit[s], 1), \
            sprintf("%d%%", rnd(failpct[s], 0))
        }
      }

      shown = 0
      for (i = 1; i <= nd; i++) {
        s = dead[i]
        if (skip6 && is6[s]) continue
        if (!shown) { print ""; print "No usable answer during warm-up (skipped):"; shown = 1 }
        printf "%-6s%-" wn "s  %-" wa "s  %s\n", "  -", sname[s], saddr[s], dead_reason(s)
      }

      print ""
      if (nr > 0) {
        s = rel[1]
        printf "Fastest: %s (%s), score %s ms.\n", sname[s], saddr[s], num(score[s], 1)
        if (ntied) {
          printf "~ %s statistically tied with it: their likely score ranges\n", \
            (ntied == 1) ? "1 other server is" : ntied " other servers are"
          print "  overlap, so the gaps between them may just be noise. Choose among the"
          print "  tied servers on features (privacy, filtering) rather than speed."
        }
      }
      if (skip6) printf "Note: %s, so this network probably has no\n      IPv6 connectivity. Left out of the results (the IPv4-only option skips IPv6).\n", \
        (n6 == 1) ? "the only IPv6 server did not answer" : "none of the " n6 " IPv6 servers answered"
      for (i = 1; i <= nb; i++) {
        split(blist[i], parts, SUBSEP)
        printf "Note: excluded %s (%s test) from scoring: it failed on most servers, so\n      the problem is that domain, not the resolvers.\n", parts[2], parts[1]
      }
      print ""
      print "Score     = average of the three medians below."
      print "Cached    = median for popular domains (mostly the network trip to the server)."
      print "Uncached  = median for random names the server must look up from scratch."
      print "Long-tail = median for less popular domains (cached or not)."
      print "p95       = 95% of lookups were this fast or faster."
      print "Jitter    = standard deviation of the cached lookups."
      print "Fail      = lookups that timed out or got no usable answer."
    }' "$1"
}

main() {
  parse_args "$@"
  if [ -n "$ANALYZE_FILE" ]; then
    [ -r "$ANALYZE_FILE" ] || die "can't read $ANALYZE_FILE"
    report "$ANALYZE_FILE"
    return
  fi
  measure
}

# Tests source this file with DNSBENCH_SOURCE_ONLY=1 to call functions directly.
if [ -z "${DNSBENCH_SOURCE_ONLY:-}" ]; then
  main "$@"
fi
