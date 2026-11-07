# Web Server Attack Analysis — "It Happened on Christmas Day" (2019-12-25)

Source: malware-traffic-analysis[.]net, 2019-12-25 traffic analysis exercise.
Analyst: Week 7 SOC lab. Tool: Wireshark 4.6, offline, in an isolated VM.

**Summary:** An external host, `139.199.184[.]166`, ran an automated scan against an Ubuntu/Apache web server (internal `10.12.25.101`, public `128.199.64[.]235`, hosted on DigitalOcean) from 06:28:52 to 06:47:35 UTC on 2019-12-25. The scanner probed for admin pages, debug files and already-planted webshells, tried two remote-code-execution payloads (ThinkCMF and a shell command injection), and finally tried TCP ports 8080 and 8983. **Every attempt failed:** of 622 HTTP requests, 615 returned 404, 1 returned 403, and the six 200 responses were the unchanged homepage; both extra ports refused the connection. **Assessment: no evidence of compromise in the network traffic.** A host-side check of the web root is still recommended (see Limits).

## Timeline (UTC)

| Time | Event | Server reply |
|---|---|---|
| 06:28:52 | First contact: `GET /` | 200, homepage ("Welcome to this server!!") |
| 06:28:52 | `GET /robots.txt` — looking for paths the site wants hidden | 404 |
| 06:28:52 | `POST /Admin1f768268/Login.php` with body `admin=die(@md5(Apri1));` — webshell test probe | 404 |
| 06:28:53 – 06:29:13 | Rapid POSTs to `/l.php`, `/phpinfo.php`, `/test.php`, `/index.php`, `/bbs.php`, `/forum.php`, `/forums.php`, `/bbs/index.php`, … | 404 |
| ~06:29:16 | `/webdav/` probe — checking for an HTTP file-upload feature | 404 |
| 06:30:08 | ThinkCMF RCE attempt: `/?a=fetch&content=<php>die(@md5(HelloThinkCMF))…` | 200, but the normal homepage (Content-Length 468) |
| 06:30:11 | Command injection attempt: `/?a=echo -n HelloNginx\|md5sum` | 200, but the normal homepage (Content-Length 468) |
| 06:30 – 06:45 | Continued wordlist of webshell names: `/shell.php`, `/cmd.php`, `/hack.php`, `/x.php`, `/qq.php`, `/1.php`, `/zzz.php`, … | 404 |
| 06:42:19 | `GET /.php` | 403 Forbidden |
| 06:45:32 | Last `GET /` | 200, homepage |
| 06:47:31 – 06:47:33 | 3 × SYN to TCP 8080 | RST, ACK (port closed) |
| 06:47:34 – 06:47:35 | 3 × SYN to TCP 8983 (Apache Solr default) | RST, ACK (port closed) |

## Other ports probed

Filtering `!(tcp.port eq 80)` shows connection attempts outside the web traffic:

| Port | Common use | Why a scanner checks it |
|---|---|---|
| TCP 8080 | Alternate HTTP, admin panels, proxies | Second web server or management interface |
| TCP 8983 | Apache Solr (default) | Solr had widely exploited remote-code-execution flaws in 2019 |

Each port got three SYN packets (the attacker's OS retrying, shown by Wireshark as "TCP Port numbers reused"), and each SYN was answered immediately by RST, ACK. The ports were closed; no handshake completed and no data was exchanged.

## Traffic at a glance

| Measure | Value |
|---|---|
| Hosts | 1 conversation: `139.199.184[.]166` ↔ `10.12.25.101` |
| Packets / TCP connections | 2,438 / 83 |
| HTTP requests | 622 (383 POST, 239 GET) |
| HTTP responses | 615 × 404, 1 × 403, 6 × 200 |
| Duration | ~19 minutes |
| Non-HTTP packets | 12 (6 SYN, 6 RST on ports 8080 and 8983) |

## Victim

- **Role:** public web server (it *received* the connections, on port 80)
- **IP:** `10.12.25.101` internal, `128.199.64[.]235` public (from the `Host:` header; the cloud provider NATs one to the other)
- **Platform:** `Server: Apache/2.4.29 (Ubuntu)`; network card vendor prefix `DigitalOcean_96:35:7c`
- **Hostname / user:** not present in the capture (no DHCP, NBNS or Kerberos traffic), which is expected for a capture taken at a single web server

## Indicators of Compromise (IOCs)

| Type | Value | Notes |
|---|---|---|
| Attacker IP | `139.199.184[.]166` | Source of all 622 requests |
| User-Agent | `Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:31.0) Gecko/20100101 Firefox/31.0` | Spoofed: Firefox 31 dates from 2014; GETs also carried a form `Content-Type`, which browsers do not send |
| Probe payload | `admin=die(@md5(Apri1));` | Expected success marker: `c0eb89e1d7f2982390f96603e66f2b6b` (not seen) |
| Exploit payload | `/?a=fetch&content=<php>die(@md5(HelloThinkCMF))` | ThinkCMF RCE; success marker `4d14d64d1cbfe8042b12f47bc5e3e432` (not seen) |
| Exploit payload | `/?a=echo -n HelloNginx\|md5sum` | Command injection; success marker `713ce499143e1c7683a8bc530415d240` (not seen) |
| Probed paths | `/Admin1f768268/Login.php`, `/phpinfo.php`, `/shell.php`, `/cmd.php`, `/hack.php`, `/qq.php`, `/1.php`, `/webdav/`, … | Typical webshell-hunting wordlist |

> Note: no file hash applies; nothing was downloaded or uploaded.

## How the "no compromise" conclusion was reached

1. **Status codes:** 615 of 622 requests were 404. A blind wordlist, not knowledge of the site.
2. **The six 200s:** three were plain `GET /`. The other three requested `/` with exploit parameters, and every one returned the same 468-byte homepage as a plain `GET /`. The server ignored the parameters.
3. **Proof strings:** each probe asks the server to compute an MD5 of a test word. If any had run, its hash would appear in a reply. Wireshark filters `frame contains "<hash>"` for all three hashes returned **no packets**.
4. **The 403:** `/.php` was refused by Apache (likely its rule protecting hidden "dot" files). A refusal, not access.

## MITRE ATT&CK mapping

- **T1595.003 Active Scanning: Wordlist Scanning** — hundreds of guessed paths
- **T1505.003 Server Software Component: Web Shell** — hunting for previously planted backdoors
- **T1190 Exploit Public-Facing Application** — ThinkCMF and command-injection attempts (attempted, unsuccessful)

## What a defender would do

- Block `139.199.184[.]166` at the firewall, and consider rate-limiting or a WAF rule for bursts of 404s from one source.
- Confirm no debug or leftover files (`phpinfo.php`, `test.php`) exist in the web root.
- Scan the web root for unexpected `.php` files and recently modified files, since the network capture cannot prove a backdoor is absent.
- Keep the CMS and Apache patched; the scanner targeted known public exploits.

## Limits of this analysis

- Network evidence shows these specific attempts failed. It cannot show what is on the server's disk.
- Apart from the 8080 and 8983 connection attempts, only HTTP on port 80 is in the capture.
- The exercise author notes several IPs scanned the server; this capture was trimmed to the most active one, so it does not show the full volume of scanning a public server receives.
- The DigitalOcean MAC vendor and server identity were sanitized by the exercise author; the scan itself was real.

## Analyst note

I first applied the endpoint-infection template (find the victim's hostname via DHCP, the download, the beacon). The empty DHCP/NBNS/Kerberos filters and the traffic direction (outside → inside on port 80) showed this was an attack *on a server*, not an infected workstation, so I switched to "did the attacker get in?" and checked every successful response.

Checked against the exercise answers afterwards: victim, attacker and verdict matched. I initially missed the connection attempts to TCP 8080 and 8983, because I filtered to HTTP early. Lesson: after analyzing the obvious protocol, filter it out (`!(tcp.port eq 80)`) and look at what remains.
