<#
.SYNOPSIS
    dns_speed_test_win.ps1

    Benchmarks ~100 public DNS resolver addresses (IPv4 and IPv6) plus your
    currently configured DNS servers, and ranks them by typical lookup time.
    Windows equivalent of dns_speed_test_macos.sh: same tests, same scoring.

.DESCRIPTION
    Right-click this file -> "Run with PowerShell"
    -- or, from a PowerShell prompt --
    powershell -ExecutionPolicy Bypass -File .\dns_speed_test_win.ps1
    powershell -ExecutionPolicy Bypass -File .\dns_speed_test_win.ps1 -Help

.NOTES
    Sends its own DNS queries over UDP and times only the network round trip
    (no PowerShell overhead included), so no extra tools are needed.
    Requires PowerShell 5.1+ (built into Windows 10/11). Also runs on
    PowerShell 7 on macOS and Linux.
#>
[CmdletBinding()]
param(
    [int]$Rounds = 3,          # rounds of each test per server
    [int]$Jobs = 8,            # servers queried at the same time (1 = one at a time)
    [int]$TimeoutSec = 2,      # seconds to wait for each answer
    [switch]$IPv4Only,         # skip IPv6 servers
    [switch]$NoSystemDns,      # don't add this machine's current DNS servers
    [string]$ServersFile,      # test the servers in this file instead of the built-in list
    [string]$RawFile,          # also save every individual measurement to this file
    [string]$Analyze,          # don't measure; re-analyze a file saved with -RawFile
    [switch]$Help
)

# ------------------------------------------------------------------ settings

# Popular domains. Big resolvers nearly always have these cached, so this test
# mostly measures the network round trip between you and the resolver.
$CachedDomains = @('google.com', 'amazon.com', 'apple.com', 'wikipedia.org', 'cloudflare.com')

# Zones for the "uncached" test. Every query asks for a random name that does
# not exist (e.g. dnsbench-1a2b3c4d5e6f.google.com). No resolver can have it
# cached, so it has to ask the zone's own servers, which is what happens on a
# real cache miss. These zones are deliberately not DNSSEC-signed: in signed
# zones, validating resolvers can answer random names from cache (RFC 8198).
$UncachedZones = @('google.com', 'amazon.com', 'microsoft.com', 'facebook.com', 'wikipedia.org')

# Less popular sites (universities, registries, open-source projects). Each
# round uses a different random selection, so a resolver may or may not have
# them cached, like the long tail of real browsing.
$LongtailDomains = @(
    'ethz.ch', 'uio.no', 'helsinki.fi', 'kuleuven.be', 'uva.nl', 'tuwien.at', 'unimelb.edu.au',
    'auckland.ac.nz', 'ubc.ca', 'kyoto-u.ac.jp', 'usp.br', 'uct.ac.za', 'unam.mx',
    'uni-heidelberg.de', 'ku.dk', 'tcd.ie', 'ed.ac.uk', 'nus.edu.sg', 'kaist.ac.kr', 'iitb.ac.in',
    'cuni.cz', 'uw.edu.pl', 'ietf.org', 'isc.org', 'nlnetlabs.nl', 'sqlite.org', 'curl.se',
    'postgresql.org', 'openbsd.org', 'gnu.org', 'ripe.net', 'apnic.net', 'lacnic.net',
    'afrinic.net', 'arin.net', 'w3.org', 'unicode.org', 'abs.gov.au', 'smhi.se', 'knmi.nl'
)
$LongtailPerRound = 5

$MaxFailPct = 10   # servers failing more than this % are listed as unreliable

# DNS servers to test: "Name Address" (optionally followed by a port).
# "-2" marks a provider's secondary address; "-v6" marks IPv6 addresses.
$Servers = @(
    # Cloudflare
    'Cloudflare                     1.1.1.1'
    'Cloudflare-2                   1.0.0.1'
    'Cloudflare-Malware-Block       1.1.1.2'
    'Cloudflare-Malware-Block-2     1.0.0.2'
    'Cloudflare-Family              1.1.1.3'
    'Cloudflare-Family-2            1.0.0.3'
    'Cloudflare-v6                  2606:4700:4700::1111'
    'Cloudflare-2-v6                2606:4700:4700::1001'
    'Cloudflare-Malware-Block-v6    2606:4700:4700::1112'
    'Cloudflare-Malware-Block-2-v6  2606:4700:4700::1002'
    'Cloudflare-Family-v6           2606:4700:4700::1113'
    'Cloudflare-Family-2-v6         2606:4700:4700::1003'
    # Google
    'Google                         8.8.8.8'
    'Google-2                       8.8.4.4'
    'Google-v6                      2001:4860:4860::8888'
    'Google-2-v6                    2001:4860:4860::8844'
    # Quad9
    'Quad9                          9.9.9.9'
    'Quad9-2                        149.112.112.112'
    'Quad9-No-Filter                9.9.9.10'
    'Quad9-No-Filter-2              149.112.112.10'
    'Quad9-ECS                      9.9.9.11'
    'Quad9-ECS-2                    149.112.112.11'
    'Quad9-v6                       2620:fe::fe'
    'Quad9-2-v6                     2620:fe::9'
    'Quad9-No-Filter-v6             2620:fe::10'
    'Quad9-No-Filter-2-v6           2620:fe::fe:10'
    'Quad9-ECS-v6                   2620:fe::11'
    'Quad9-ECS-2-v6                 2620:fe::fe:11'
    # OpenDNS (Cisco)
    'OpenDNS                        208.67.222.222'
    'OpenDNS-2                      208.67.220.220'
    'OpenDNS-FamilyShield           208.67.222.123'
    'OpenDNS-FamilyShield-2         208.67.220.123'
    'OpenDNS-v6                     2620:119:35::35'
    'OpenDNS-2-v6                   2620:119:53::53'
    'OpenDNS-FamilyShield-v6        2620:119:35::123'
    'OpenDNS-FamilyShield-2-v6      2620:119:53::123'
    # Control D (free, unfiltered)
    'Control-D                      76.76.2.0'
    'Control-D-2                    76.76.10.0'
    'Control-D-v6                   2606:1a40::'
    'Control-D-2-v6                 2606:1a40:1::'
    # AdGuard
    'AdGuard                        94.140.14.14'
    'AdGuard-2                      94.140.15.15'
    'AdGuard-Family                 94.140.14.15'
    'AdGuard-Family-2               94.140.15.16'
    'AdGuard-Unfiltered             94.140.14.140'
    'AdGuard-Unfiltered-2           94.140.14.141'
    'AdGuard-v6                     2a10:50c0::ad1:ff'
    'AdGuard-2-v6                   2a10:50c0::ad2:ff'
    'AdGuard-Family-v6              2a10:50c0::bad1:ff'
    'AdGuard-Family-2-v6            2a10:50c0::bad2:ff'
    'AdGuard-Unfiltered-v6          2a10:50c0::1:ff'
    'AdGuard-Unfiltered-2-v6        2a10:50c0::2:ff'
    # NextDNS (anycast, no profile)
    'NextDNS                        45.90.28.0'
    'NextDNS-2                      45.90.30.0'
    'NextDNS-v6                     2a07:a8c0::'
    'NextDNS-2-v6                   2a07:a8c1::'
    # CleanBrowsing
    'CleanBrowsing-Security         185.228.168.9'
    'CleanBrowsing-Security-2       185.228.169.9'
    'CleanBrowsing-Family           185.228.168.168'
    'CleanBrowsing-Family-2         185.228.169.168'
    'CleanBrowsing-Adult            185.228.168.10'
    'CleanBrowsing-Adult-2          185.228.169.11'
    'CleanBrowsing-Security-v6      2a0d:2a00:1::2'
    'CleanBrowsing-Security-2-v6    2a0d:2a00:2::2'
    'CleanBrowsing-Family-v6        2a0d:2a00:1::'
    'CleanBrowsing-Family-2-v6      2a0d:2a00:2::'
    'CleanBrowsing-Adult-v6         2a0d:2a00:1::1'
    'CleanBrowsing-Adult-2-v6       2a0d:2a00:2::1'
    # Comodo Secure DNS
    'Comodo-Secure                  8.26.56.26'
    'Comodo-Secure-2                8.20.247.20'
    # UltraDNS Public (Vercara/DigiCert; formerly Verisign and Neustar)
    'UltraDNS                       64.6.64.6'
    'UltraDNS-2                     64.6.65.6'
    'UltraDNS-Threat                156.154.70.2'
    'UltraDNS-Threat-2              156.154.71.2'
    'UltraDNS-v6                    2620:74:1b::1:1'
    'UltraDNS-2-v6                  2620:74:1c::2:2'
    'UltraDNS-Threat-v6             2610:a1:1018::2'
    'UltraDNS-Threat-2-v6           2610:a1:1019::2'
    # Level3 / Lumen (long-standing, though never an official public service)
    'Level3                         4.2.2.1'
    'Level3-2                       4.2.2.2'
    # DNS.Watch
    'DNS-Watch                      84.200.69.80'
    'DNS-Watch-2                    84.200.70.40'
    # Yandex
    'Yandex                         77.88.8.8'
    'Yandex-2                       77.88.8.1'
    'Yandex-Safe                    77.88.8.88'
    'Yandex-Family                  77.88.8.7'
    'Yandex-v6                      2a02:6b8::feed:0ff'
    'Yandex-2-v6                    2a02:6b8:0:1::feed:0ff'
    'Yandex-Safe-v6                 2a02:6b8::feed:bad'
    'Yandex-Family-v6               2a02:6b8::feed:a11'
    # Alternate DNS
    'Alternate-DNS                  76.76.19.19'
    'Alternate-DNS-2                76.223.122.150'
    # UncensoredDNS
    'UncensoredDNS                  91.239.100.100'
    'UncensoredDNS-2                89.233.43.71'
    'UncensoredDNS-v6               2001:67c:28a4::'
    'UncensoredDNS-2-v6             2a01:3a0:53:53::'
    # DNS4EU (EU-backed public resolver)
    'DNS4EU-Protective              86.54.11.1'
    'DNS4EU-Protective-2            86.54.11.201'
    'DNS4EU-Unfiltered              86.54.11.100'
    'DNS4EU-Unfiltered-2            86.54.11.200'
    'DNS4EU-Protective-v6           2a13:1001::86:54:11:1'
    'DNS4EU-Protective-2-v6         2a13:1001::86:54:11:201'
    'DNS4EU-Unfiltered-v6           2a13:1001::86:54:11:100'
    'DNS4EU-Unfiltered-2-v6         2a13:1001::86:54:11:200'
    # Gcore
    'Gcore                          95.85.95.85'
    'Gcore-2                        2.56.220.2'
    'Gcore-v6                       2a03:90c0:999d::1'
    'Gcore-2-v6                     2a03:90c0:9992::1'
)

# ---------------------------------------------------------------- internals

$Inv = [Globalization.CultureInfo]::InvariantCulture
$Sep = [string][char]0x1c   # joins test + target, sorts like awk's SUBSEP

function Show-Usage {
    @'
Usage: dns_speed_test_win.ps1 [options]

  -Rounds N          rounds of each test per server (default 3)
  -Jobs N            servers to query at the same time (default 8;
                     1 = one at a time)
  -TimeoutSec SEC    seconds to wait for each answer (default 2)
  -IPv4Only          skip IPv6 servers
  -NoSystemDns       don't add this machine's current DNS servers
  -ServersFile FILE  test the servers listed in FILE instead of the
                     built-in list (one per line: Name Address [Port];
                     lines starting with # are ignored)
  -RawFile FILE      also save every individual measurement to FILE
                     (tab-separated)
  -Analyze FILE      don't measure anything; re-analyze a file saved
                     earlier with -RawFile
  -Help              show this help
'@ -split "`n" | ForEach-Object { Write-Host $_.TrimEnd("`r") }
}

function Stop-WithError([string]$Message) {
    Write-Host "Error: $Message" -ForegroundColor Red
    exit 1
}

function Resolve-UserPath([string]$Path) {
    $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

# True for addresses that only reach your own machine, router or LAN
# (private, loopback, link-local, CGNAT, unique-local, site-local). Timing
# those measures the hop to the router, not real upstream DNS.
function Test-LocalAddress([string]$Address) {
    $a = $Address.ToLowerInvariant()
    $pct = $a.IndexOf('%')
    if ($pct -ge 0) { $a = $a.Substring(0, $pct) }                 # zone index like %12
    if ($a.StartsWith('::ffff:') -and $a.Contains('.')) { $a = $a.Substring(7) }  # IPv4-mapped
    $patterns = @('^10\.', '^127\.', '^0\.', '^169\.254\.', '^192\.168\.',
                  '^172\.(1[6-9]|2[0-9]|3[01])\.',
                  '^100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.',
                  '^::1?$', '^fe[89ab][0-9a-f]:', '^fe[c-f][0-9a-f]:', '^f[cd][0-9a-f][0-9a-f]:')
    foreach ($p in $patterns) { if ($a -cmatch $p) { return $true } }
    return $false
}

# DNS servers of connected network adapters (IPv4 and IPv6).
function Get-SystemDns {
    if (-not (Get-Command Get-DnsClientServerAddress -ErrorAction SilentlyContinue)) { return @() }
    try {
        $connected = @()
        if (Get-Command Get-NetIPInterface -ErrorAction SilentlyContinue) {
            $connected = @(Get-NetIPInterface -ConnectionState Connected -ErrorAction SilentlyContinue |
                ForEach-Object { $_.InterfaceIndex } | Select-Object -Unique)
        }
        $list = @(Get-DnsClientServerAddress -ErrorAction Stop | Where-Object {
                $_.ServerAddresses.Count -gt 0 -and $_.InterfaceAlias -notmatch 'Loopback' -and
                ($connected.Count -eq 0 -or $connected -contains $_.InterfaceIndex)
            } | ForEach-Object { $_.ServerAddresses })
        return @($list | Select-Object -Unique)
    } catch {
        return @()
    }
}

function New-Server([string]$Name, [string]$Address, [int]$Port) {
    [pscustomobject]@{
        Name    = $Name
        Address = $Address
        Port    = $Port
        Raw     = New-Object 'System.Collections.Generic.List[string]'
    }
}

function Add-ServerLine($List, [string]$Line) {
    $parts = @($Line.Trim() -split '\s+' | Where-Object { $_ -ne '' })
    if ($parts.Count -eq 0) { return }
    $addr = if ($parts.Count -ge 2) { $parts[1] } else { '' }
    if (-not ($addr.Contains('.') -or $addr.Contains(':'))) {
        Stop-WithError "bad server entry (expected: Name Address [Port]): $Line"
    }
    $port = 53
    if ($parts.Count -ge 3) {
        if ($parts[2] -notmatch '^[0-9]+$') { Stop-WithError "bad port in server entry: $Line" }
        $port = [int]$parts[2]
    }
    if ($IPv4Only -and $addr.Contains(':')) { return }
    $List.Add((New-Server $parts[0] $addr $port))
}

function Get-ServerList {
    $list = New-Object 'System.Collections.Generic.List[object]'
    if ($ServersFile) {
        $path = Resolve-UserPath $ServersFile
        if (-not (Test-Path -LiteralPath $path)) { Stop-WithError "can't read $ServersFile" }
        foreach ($line in [IO.File]::ReadAllLines($path)) {
            $hash = $line.IndexOf('#')
            if ($hash -ge 0) { $line = $line.Substring(0, $hash) }
            Add-ServerLine $list $line
        }
    } else {
        foreach ($entry in $Servers) { Add-ServerLine $list $entry }
    }

    if (-not $NoSystemDns) {
        $i = 1
        foreach ($ip in (Get-SystemDns)) {
            if (Test-LocalAddress $ip) {
                Write-Host ("Note: skipping {0}, your current DNS. It is a local/router address, so it" -f $ip) -ForegroundColor DarkYellow
                Write-Host  "      would only measure the hop to your router, not real upstream DNS." -ForegroundColor DarkYellow
                continue
            }
            if ($IPv4Only -and $ip.Contains(':')) { continue }
            $existing = $list | Where-Object { $_.Address -eq $ip -and $_.Port -eq 53 } | Select-Object -First 1
            if ($existing) {
                Write-Host ("Note: your current DNS {0} is already in the list as {1}." -f $ip, $existing.Name)
                continue
            }
            $list.Add((New-Server "Current-DNS-$i" $ip 53))
            $i++
        }
    }
    return , $list
}

# Runs inside a runspace: queries each name in turn and returns one line per
# query: test, target, status, milliseconds.
$WorkerScript = {
    param([string]$Address, [int]$Port, [string]$Category, [string[]]$Names, [int]$TimeoutMs)

    # Sends one A query over UDP and returns @(status, ms). The stopwatch only
    # covers sending the packet and receiving the answer.
    function Send-DnsQuery([string]$Server, [int]$Port, [string]$Name, [int]$TimeoutMs) {
        $id = Get-Random -Minimum 0 -Maximum 65536
        $q = New-Object 'System.Collections.Generic.List[byte]'
        # header: id, flags = recursion desired, 1 question, 0 answers, 0 authority, 1 additional (EDNS)
        $q.AddRange([byte[]]@((($id -shr 8) -band 0xFF), ($id -band 0xFF), 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01))
        foreach ($label in $Name.TrimEnd('.').Split('.')) {
            $b = [Text.Encoding]::ASCII.GetBytes($label)
            $q.Add([byte]$b.Length)
            $q.AddRange($b)
        }
        $q.AddRange([byte[]]@(0x00, 0x00, 0x01, 0x00, 0x01))   # end of name, type A, class IN
        $q.AddRange([byte[]]@(0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00))  # EDNS(0), 1232-byte UDP
        $packet = $q.ToArray()

        $ip = [Net.IPAddress]::Parse($Server)
        $udp = New-Object Net.Sockets.UdpClient($ip.AddressFamily)
        try {
            $udp.Client.ReceiveTimeout = $TimeoutMs
            $udp.Connect($ip, $Port)
            $sw = [Diagnostics.Stopwatch]::StartNew()
            [void]$udp.Send($packet, $packet.Length)
            $from = New-Object Net.IPEndPoint($ip, 0)
            while ($true) {
                $resp = $udp.Receive([ref]$from)
                if ($resp.Length -ge 12 -and $resp[0] -eq $packet[0] -and $resp[1] -eq $packet[1]) { break }
                if ($sw.ElapsedMilliseconds -ge $TimeoutMs) { return @('TIMEOUT', '-') }
            }
            $sw.Stop()
            $rcode = [int]($resp[3] -band 0x0F)
            $names = @('NOERROR', 'FORMERR', 'SERVFAIL', 'NXDOMAIN', 'NOTIMP', 'REFUSED')
            $status = if ($rcode -lt $names.Count) { $names[$rcode] } else { "RCODE$rcode" }
            return @($status, $sw.Elapsed.TotalMilliseconds)
        } catch {
            $ex = $_.Exception
            while ($ex -and -not ($ex -is [Net.Sockets.SocketException])) { $ex = $ex.InnerException }
            if ($ex -and ($ex.SocketErrorCode -eq [Net.Sockets.SocketError]::TimedOut)) { return @('TIMEOUT', '-') }
            return @('NETERR', '-')
        } finally {
            $udp.Close()
        }
    }

    $inv = [Globalization.CultureInfo]::InvariantCulture
    foreach ($n in $Names) {
        $qname = $n
        if ($Category -eq 'uncached') {
            $qname = 'dnsbench-{0:x4}{1:x4}{2:x4}.{3}' -f (Get-Random -Maximum 65536), (Get-Random -Maximum 65536), (Get-Random -Maximum 65536), $n
        }
        $r = Send-DnsQuery $Address $Port $qname $TimeoutMs
        $ms = if ($r[1] -is [double]) { $r[1].ToString('0.###', $inv) } else { '-' }
        "{0}`t{1}`t{2}`t{3}" -f $Category, $n, $r[0], $ms
    }
}

# Runs one pass: every active server, in random order, at most -Jobs at once.
# Each pass covers all servers, so a brief network hiccup affects every
# server a little instead of one server a lot.
function Invoke-Pass([string]$Label, [string]$Category, [string[]]$Names) {
    Write-Host ('  {0,-46}' -f $Label) -NoNewline
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $active = @($script:Active)
    if ($active.Count -gt 0) {
        $order = @(Get-Random -InputObject $active -Count $active.Count)
        $tasks = New-Object 'System.Collections.Generic.List[object]'
        foreach ($s in $order) {
            $ps = [powershell]::Create()
            $ps.RunspacePool = $script:Pool
            [void]$ps.AddScript($WorkerScript.ToString())
            [void]$ps.AddArgument($s.Address).AddArgument($s.Port).AddArgument($Category).AddArgument($Names).AddArgument($TimeoutSec * 1000)
            $tasks.Add([pscustomobject]@{ Server = $s; PS = $ps; Handle = $ps.BeginInvoke() })
        }
        foreach ($t in $tasks) {
            try {
                foreach ($line in $t.PS.EndInvoke($t.Handle)) { $t.Server.Raw.Add([string]$line) }
            } finally {
                $t.PS.Dispose()
            }
        }
    }
    Write-Host ('done ({0}s)' -f [int][math]::Floor($sw.Elapsed.TotalSeconds))
}

function Test-AnsweredWarmup($Server) {
    foreach ($line in $Server.Raw) {
        $f = $line.Split("`t")
        if ($f[0] -eq 'warmup' -and ($f[2] -eq 'NOERROR' -or $f[2] -eq 'NXDOMAIN')) { return $true }
    }
    return $false
}

function Invoke-Measure {
    $list = Get-ServerList
    if ($list.Count -eq 0) { Stop-WithError 'no servers to test' }
    $n6 = @($list | Where-Object { $_.Address.Contains(':') }).Count
    $n4 = $list.Count - $n6
    $perRound = $CachedDomains.Count + $UncachedZones.Count + $LongtailPerRound

    Write-Host ''
    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ' DNS Latency Benchmark'
    Write-Host (' {0} servers ({1} IPv4, {2} IPv6), {3} timed lookups each' -f $list.Count, $n4, $n6, ($perRound * $Rounds))
    $rword = if ($Rounds -eq 1) { 'round' } else { 'rounds' }
    Write-Host (' ({0} {1} of: popular domains, random uncached names, long-tail domains)' -f $Rounds, $rword)
    Write-Host (' {0} servers at a time, {1}s timeout per lookup' -f $Jobs, $TimeoutSec)
    Write-Host '======================================================================' -ForegroundColor Green
    Write-Host ''

    $script:Pool = [runspacefactory]::CreateRunspacePool(1, $Jobs)
    $script:Pool.Open()
    try {
        # Warm-up: two untimed queries per server. They prime ARP/NAT/route
        # state and tell us which servers answer at all; the rest are skipped.
        $script:Active = $list.ToArray()
        Invoke-Pass 'Warm-up (not scored)' 'warmup' @($CachedDomains[0], $CachedDomains[1])
        $script:Active = @($list | Where-Object { Test-AnsweredWarmup $_ })
        Write-Host ('  {0} of {1} servers answered.' -f $script:Active.Count, $list.Count)

        # A fresh random selection of long-tail domains for every round.
        $ltPool = @(Get-Random -InputObject $LongtailDomains -Count $LongtailDomains.Count)
        for ($r = 1; $r -le $Rounds; $r++) {
            foreach ($cat in @(Get-Random -InputObject @('cached', 'uncached', 'longtail') -Count 3)) {
                switch ($cat) {
                    'cached' {
                        Invoke-Pass "Round $r/${Rounds}: popular domains (cached)" 'cached' $CachedDomains
                    }
                    'uncached' {
                        Invoke-Pass "Round $r/${Rounds}: random names (uncached)" 'uncached' $UncachedZones
                    }
                    'longtail' {
                        $names = @(for ($k = 0; $k -lt $LongtailPerRound; $k++) {
                                $ltPool[((($r - 1) * $LongtailPerRound) + $k) % $ltPool.Count]
                            })
                        Invoke-Pass "Round $r/${Rounds}: less popular domains (long tail)" 'longtail' $names
                    }
                }
            }
        }
    } finally {
        $script:Pool.Close()
        $script:Pool.Dispose()
    }

    # Combine everything into one table: server, address, port, test, target,
    # status, ms.
    $raw = New-Object 'System.Collections.Generic.List[string]'
    $raw.Add("server`taddress`tport`ttest`ttarget`tstatus`tms")
    foreach ($s in $list) {
        foreach ($line in $s.Raw) { $raw.Add(("{0}`t{1}`t{2}`t{3}" -f $s.Name, $s.Address, $s.Port, $line)) }
    }
    if ($RawFile) {
        [IO.File]::WriteAllLines((Resolve-UserPath $RawFile), $raw.ToArray())
    }
    foreach ($line in (Get-Report $raw.ToArray())) { Write-Host $line }
    if ($RawFile) { Write-Host ''; Write-Host "Every measurement was saved to $RawFile" }
    Write-Host ''
    Write-Host 'Tip: run this a few times (e.g. morning and evening), since results'
    Write-Host 'vary with network conditions and time of day.'
}

# ------------------------------------------------------------------- report
# Same rules as report() in dns_speed_test_macos.sh; tests check both agree.
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
# Servers above $MaxFailPct are listed as unreliable instead of ranked. A
# domain that fails on most servers is a problem with that domain, not the
# resolvers, so it's excluded from scoring.

function Get-Rounded([double]$x, [int]$d) {
    $m = [math]::Pow(10, $d)
    return [math]::Floor($x * $m + 0.5) / $m
}

function Format-Num($x, [int]$d) {
    if ($null -eq $x) { return 'n/a' }
    return (Get-Rounded $x $d).ToString("F$d", $Inv)
}

function Get-Median($a) {
    $n = $a.Count
    if ($n % 2) { return $a[($n + 1) / 2 - 1] }
    return ($a[$n / 2 - 1] + $a[$n / 2]) / 2
}

function Get-CiLow($a) {
    $n = $a.Count
    $k = [int][math]::Floor($n / 2 - 0.98 * [math]::Sqrt($n))
    if ($k -lt 1) { $k = 1 }
    return $a[$k - 1]
}

function Get-CiHigh($a) {
    $n = $a.Count
    $k = [int][math]::Ceiling($n / 2 + 1 + 0.98 * [math]::Sqrt($n))
    if ($k -gt $n) { $k = $n }
    return $a[$k - 1]
}

function Get-StdDev($a) {
    $n = $a.Count
    if ($n -lt 2) { return 0.0 }
    $m = 0.0
    foreach ($v in $a) { $m += $v }
    $m /= $n
    $ss = 0.0
    foreach ($v in $a) { $ss += ($v - $m) * ($v - $m) }
    return [math]::Sqrt($ss / ($n - 1))
}

function Get-Report([string[]]$Lines) {
    $cats = @('cached', 'uncached', 'longtail')
    $servers = New-Object 'System.Collections.Generic.List[object]'
    $byKey = New-Object 'System.Collections.Generic.Dictionary[string,object]'
    $records = New-Object 'System.Collections.Generic.List[object]'
    $tAtt = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $tFail = New-Object 'System.Collections.Generic.Dictionary[string,int]'
    $tSrv = New-Object 'System.Collections.Generic.Dictionary[string,object]'

    for ($ln = 0; $ln -lt $Lines.Count; $ln++) {
        $f = $Lines[$ln].TrimEnd("`r").Split("`t")
        if ($ln -eq 0 -and $f.Count -ge 4 -and $f[0] -eq 'server' -and $f[3] -eq 'test') { continue }
        if ($f.Count -lt 7) { continue }
        $key = $f[0] + $Sep + $f[1] + $Sep + $f[2]
        if (-not $byKey.ContainsKey($key)) {
            $srv = [pscustomobject]@{
                Index = $servers.Count + 1; Name = $f[0]; Address = $f[1]
                WTotal = 0; WOk = 0; WStatus = @{}; WLast = ''
                Vals = @{ cached = (New-Object 'System.Collections.Generic.List[double]');
                          uncached = (New-Object 'System.Collections.Generic.List[double]');
                          longtail = (New-Object 'System.Collections.Generic.List[double]') }
                All = New-Object 'System.Collections.Generic.List[double]'
                Att = 0; Fails = 0
                Reach = $false; HasScore = $false; Score = 0.0; ScoreLo = 0.0; ScoreHi = 0.0
                Med = @($null, $null, $null); Jitter = $null; P95 = $null; FailPct = 0.0
                Is6 = $f[1].Contains(':'); Tied = $false
            }
            $servers.Add($srv)
            $byKey[$key] = $srv
        }
        $s = $byKey[$key]
        $cat = $f[3]; $st = $f[5]
        $ok = ($st -ceq 'NOERROR' -or $st -ceq 'NXDOMAIN')
        if ($cat -ceq 'warmup') {
            $s.WTotal++
            if ($ok) { $s.WOk++ } else { $s.WStatus[$st] = $true; $s.WLast = $st }
            continue
        }
        if ($cats -cnotcontains $cat) { continue }
        $t = $cat + $Sep + $f[4]
        $ms = 0.0
        [void][double]::TryParse($f[6], [Globalization.NumberStyles]::Float, $Inv, [ref]$ms)
        $records.Add([pscustomobject]@{ S = $s; Cat = $cat; T = $t; Ok = $ok; Ms = $ms })
        if (-not $tAtt.ContainsKey($t)) { $tAtt[$t] = 0; $tFail[$t] = 0; $tSrv[$t] = New-Object 'System.Collections.Generic.HashSet[int]' }
        $tAtt[$t]++
        if (-not $ok) { $tFail[$t]++ }
        [void]$tSrv[$t].Add($s.Index)
    }

    # targets that failed most of the time, across at least 3 servers
    $broken = New-Object 'System.Collections.Generic.List[string]'
    foreach ($t in $tAtt.Keys) {
        if ($tSrv[$t].Count -ge 3 -and $tFail[$t] * 2 -gt $tAtt[$t]) { $broken.Add($t) }
    }
    $brokenArr = $broken.ToArray()
    [Array]::Sort($brokenArr, [StringComparer]::Ordinal)
    $brokenSet = New-Object 'System.Collections.Generic.HashSet[string]' (, [string[]]$brokenArr)

    foreach ($rec in $records) {
        if ($brokenSet.Contains($rec.T)) { continue }
        $rec.S.Att++
        if ($rec.Ok) { $rec.S.Vals[$rec.Cat].Add($rec.Ms); $rec.S.All.Add($rec.Ms) } else { $rec.S.Fails++ }
    }

    $rel = New-Object 'System.Collections.Generic.List[object]'
    $unrel = New-Object 'System.Collections.Generic.List[object]'
    $dead = New-Object 'System.Collections.Generic.List[object]'
    $count6 = 0; $count6ok = 0
    foreach ($s in $servers) {
        $s.Reach = ($s.WOk -gt 0 -or $s.WTotal -eq 0)
        if ($s.Is6) { $count6++; if ($s.Reach) { $count6ok++ } }
        if (-not $s.Reach) { $dead.Add($s); continue }

        $s.HasScore = $true; $sum = 0.0; $lo = 0.0; $hi = 0.0
        for ($c = 0; $c -lt 3; $c++) {
            $v = $s.Vals[$cats[$c]]
            if ($v.Count -eq 0) { $s.HasScore = $false; continue }
            $v.Sort()
            $s.Med[$c] = Get-Median $v
            $sum += $s.Med[$c]; $lo += Get-CiLow $v; $hi += Get-CiHigh $v
            if ($c -eq 0) { $s.Jitter = Get-StdDev $v }
        }
        if ($s.HasScore) { $s.Score = $sum / 3; $s.ScoreLo = $lo / 3; $s.ScoreHi = $hi / 3 }
        if ($s.All.Count -gt 0) {
            $s.All.Sort()
            $s.P95 = $s.All[[int][math]::Floor((95 * $s.All.Count + 99) / 100) - 1]
        }
        $s.FailPct = if ($s.Att -gt 0) { 100.0 * $s.Fails / $s.Att } else { 0.0 }
        if ($s.HasScore -and $s.FailPct -le $MaxFailPct) { $rel.Add($s) } else { $unrel.Add($s) }
    }
    $rel = @($rel | Sort-Object -Property Score, FailPct, Index)
    $unrel = @($unrel | Sort-Object -Property FailPct, @{ Expression = { -[int]$_.HasScore } },
        @{ Expression = { if ($_.HasScore) { $_.Score } else { 0.0 } } }, Index)

    $ntied = 0
    if ($rel.Count -gt 0) {
        $lead = $rel[0]
        for ($i = 1; $i -lt $rel.Count; $i++) {
            if ($rel[$i].ScoreLo -le $lead.ScoreHi) { $rel[$i].Tied = $true; $ntied++ }
        }
        if ($ntied) { $lead.Tied = $true }
    }
    $skip6 = ($count6 -gt 0 -and $count6ok -eq 0)

    $wn = 'Server'.Length; $wa = 'Address'.Length
    foreach ($s in $servers) {
        if (-not $s.Reach -and $skip6 -and $s.Is6) { continue }
        if ($s.Name.Length -gt $wn) { $wn = $s.Name.Length }
        if ($s.Address.Length -gt $wa) { $wa = $s.Address.Length }
    }
    $row = '{0,-6}{1,-' + $wn + '}  {2,-' + $wa + '}  {3,6}  {4,6}  {5,8}  {6,9}  {7,5}  {8,6}  {9,4}'
    $bar = '======================================================================'

    $out = New-Object 'System.Collections.Generic.List[string]'
    $out.Add(''); $out.Add($bar); $out.Add(' Results (milliseconds, lower is better)'); $out.Add($bar)
    if ($rel.Count -eq 0) {
        $out.Add('No server answered reliably enough to rank.')
    } else {
        $out.Add(($row -f 'Rank', 'Server', 'Address', 'Score', 'Cached', 'Uncached', 'Long-tail', 'p95', 'Jitter', 'Fail'))
        for ($i = 0; $i -lt $rel.Count; $i++) {
            $s = $rel[$i]
            $mark = if ($s.Tied) { '~' } else { ' ' }
            $out.Add(($row -f ('{0,3}{1}' -f ($i + 1), $mark), $s.Name, $s.Address, (Format-Num $s.Score 1),
                    (Format-Num $s.Med[0] 1), (Format-Num $s.Med[1] 1), (Format-Num $s.Med[2] 1),
                    (Format-Num $s.P95 0), (Format-Num $s.Jitter 1), ('{0}%' -f [int](Get-Rounded $s.FailPct 0))))
        }
    }

    if ($unrel.Count -gt 0) {
        $out.Add('')
        $out.Add(('Unreliable (more than {0}% of lookups failed, or a test never succeeded):' -f $MaxFailPct))
        foreach ($s in $unrel) {
            $score = if ($s.HasScore) { $s.Score } else { $null }
            $out.Add(($row -f '  -', $s.Name, $s.Address, (Format-Num $score 1),
                    (Format-Num $s.Med[0] 1), (Format-Num $s.Med[1] 1), (Format-Num $s.Med[2] 1),
                    (Format-Num $s.P95 0), (Format-Num $s.Jitter 1), ('{0}%' -f [int](Get-Rounded $s.FailPct 0))))
        }
    }

    $shown = $false
    foreach ($s in $dead) {
        if ($skip6 -and $s.Is6) { continue }
        if (-not $shown) { $out.Add(''); $out.Add('No usable answer during warm-up (skipped):'); $shown = $true }
        $reason = if ($s.WStatus.ContainsKey('TIMEOUT')) { 'no response (timed out)' }
                  elseif ($s.WStatus.ContainsKey('NETERR')) { 'network error (unreachable or refused)' }
                  elseif ($s.WStatus.ContainsKey('REFUSED')) { 'refused our queries' }
                  elseif ($s.WStatus.ContainsKey('SERVFAIL')) { 'answered SERVFAIL (server failure)' }
                  else { "no usable answer ($($s.WLast))" }
        $out.Add((('{0,-6}{1,-' + $wn + '}  {2,-' + $wa + '}  {3}') -f '  -', $s.Name, $s.Address, $reason))
    }

    $out.Add('')
    if ($rel.Count -gt 0) {
        $s = $rel[0]
        $out.Add(('Fastest: {0} ({1}), score {2} ms.' -f $s.Name, $s.Address, (Format-Num $s.Score 1)))
        if ($ntied) {
            $tiedText = if ($ntied -eq 1) { '1 other server is' } else { "$ntied other servers are" }
            $out.Add(('~ {0} statistically tied with it: their likely score ranges' -f $tiedText))
            $out.Add('  overlap, so the gaps between them may just be noise. Choose among the')
            $out.Add('  tied servers on features (privacy, filtering) rather than speed.')
        }
    }
    if ($skip6) {
        $what = if ($count6 -eq 1) { "the only IPv6 server did not answer" } else { "none of the $count6 IPv6 servers answered" }
        $out.Add(('Note: {0}, so this network probably has no' -f $what))
        $out.Add('      IPv6 connectivity. Left out of the results (the IPv4-only option skips IPv6).')
    }
    foreach ($t in $brokenArr) {
        $parts = $t.Split([char]0x1c)
        $out.Add(('Note: excluded {0} ({1} test) from scoring: it failed on most servers, so' -f $parts[1], $parts[0]))
        $out.Add('      the problem is that domain, not the resolvers.')
    }
    $out.Add('')
    $out.Add('Score     = average of the three medians below.')
    $out.Add('Cached    = median for popular domains (mostly the network trip to the server).')
    $out.Add('Uncached  = median for random names the server must look up from scratch.')
    $out.Add('Long-tail = median for less popular domains (cached or not).')
    $out.Add('p95       = 95% of lookups were this fast or faster.')
    $out.Add('Jitter    = standard deviation of the cached lookups.')
    $out.Add('Fail      = lookups that timed out or got no usable answer.')
    return , $out.ToArray()
}

# --------------------------------------------------------------------- main

function Invoke-Main {
    if ($Help) { Show-Usage; return }
    if ($Rounds -lt 1) { Stop-WithError '-Rounds must be at least 1' }
    if ($Jobs -lt 1) { Stop-WithError '-Jobs must be at least 1' }
    if ($TimeoutSec -lt 1) { Stop-WithError '-TimeoutSec must be at least 1' }
    if ($Analyze) {
        $path = Resolve-UserPath $Analyze
        if (-not (Test-Path -LiteralPath $path)) { Stop-WithError "can't read $Analyze" }
        foreach ($line in (Get-Report ([IO.File]::ReadAllLines($path)))) { Write-Host $line }
        return
    }
    Invoke-Measure
}

# Tests dot-source this file with DNSBENCH_SOURCE_ONLY=1 to call functions directly.
if (-not $env:DNSBENCH_SOURCE_ONLY) {
    Invoke-Main
}
