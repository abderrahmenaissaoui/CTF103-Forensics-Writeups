# Dead Drop on Ocean Drive

**Author:**

---

## Challenge Description
>
> Vice City, 1986. Under the pink neon of Ocean Drive, the Night Ledger crew has one golden rule: never carry a secret on paper. Paper gets lost, paper gets burned, paper gets read by the wrong cop.
>
> So last night the crew did something smarter...
>
> Our sniffer on the wire caught everything, including a few other couriers running their own errands on the same night.
>
> The capture is attached (`dead_drop.pcap`).
>

---

## Solution

---

### 1. Inspect the capture

Open `dead_drop.pcap` in Wireshark. Most of it is TLS traffic, which is encrypted and unreadable, plus some DNS, NTP and ARP. The only readable traffic is HTTP, so filter on it:

```
http
```

Among a few normal `GET` requests (`/index.html`, `/taxi/rates.json`, ...) there are thousands of `POST /api/ocean-drive/stash` requests. That is the odd traffic.

---

### 2. Read one request

Open any of those requests and look at the HTTP headers:

```
POST /api/ocean-drive/stash HTTP/1.1
Host: 10.19.86.50:8686
User-Agent: VCCourier/1.0
X-Stash-Index: 363
X-Stash-Total: 543
Content-Type: application/octet-stream
Content-Length: 1200
```

The body is a short piece of base64. Together with the headers this tells us:

* `X-Stash-Total: 543`: a file was cut into 543 pieces.
* `X-Stash-Index: 363`: this request carries piece number 363.
* `Host: 10.19.86.50:8686`: the place the piece was sent to.

So the crew mailed a file piece by piece. We need to collect the pieces, put them in the right order and decode them.

---

### 3. Find the drop boxes

Every request is sent in its own connection, so *Follow TCP Stream* only shows one piece. What changes between requests is the destination, the `Host:` header. List the destinations:

```bash
tshark -r dead_drop.pcap -Y 'http.request.method == "POST" && http.request.uri contains "stash"' -T fields -e ip.dst -e tcp.dstport | sort | uniq -c
```

```
    120 10.19.86.1      6666
    201 10.19.86.1      6669
    150 10.19.86.1      9999
    180 10.19.86.2      8081
    141 10.19.86.2      8082
    160 10.19.86.2      9997
    543 10.19.86.50     8686
    543 10.19.86.50     8687
     89 192.168.1.100   8888
    100 192.168.1.100   9998
```

Each IP and port is a **drop box**, and each box holds the pieces of one parcel. There are ten of them, so only one is the real secret and the others are other couriers' errands. (The `POST` in the filter matters: newer Wireshark also copies the URI into the server replies, which would add fake lines.)

---

### 4. Rebuild a drop box

Take one box and rebuild it, for example the biggest ones (a picture is a big file), `10.19.86.50` on port `8686`:

```bash
tshark -r dead_drop.pcap -Y 'ip.dst==10.19.86.50 && tcp.dstport==8686 && http.request.method=="POST"' -T fields -e http.request.line -e http.file_data |
  sort -t: -k5,5n | cut -f2 | tr -d '\n' | xxd -r -p | base64 -d > flag.jpg

file flag.jpg
```

What it does:

* `-e http.request.line` prints the headers, because the index is only there, and `-e http.file_data` prints the body as hex. The pieces are not in order in the capture, so the index is needed to sort them. tshark puts a tab between the two fields.
* `sort -t: -k5,5n` cuts each line at the `:` characters and sorts on field 5 as a number. Field 5 starts with the index value.
* `cut -f2` keeps what comes after the tab, the hex body, and drops the headers.
* `tr -d '\n'` joins the pieces, `xxd -r -p` turns the hex back into base64 text, and `base64 -d` decodes it into the file.

Then look at what `file` says:

* `data` means the bytes mean nothing, so this box is a decoy. Change the IP and port in the filter and try another box.
* `JPEG image data ... 1920x1080` means we found a real picture. This is what `10.19.86.50:8686` prints.
* `JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16` with no size is a fake: a JPEG header followed by garbage (`10.19.86.1:6669`).

---

#### What happens with the other drop boxes

Change only the IP and port in the filter (here `10.19.86.50` on port `8687`, the other big box):

```bash
tshark -r dead_drop.pcap -Y 'ip.dst==10.19.86.50 && tcp.dstport==8687 && http.request.method=="POST"' -T fields -e http.request.line -e http.file_data |
  sort -t: -k5,5n | cut -f2 | tr -d '\n' | xxd -r -p | base64 -d > flag.jpg

file flag.jpg
```

```
flag.jpg: data
```

`data` means `file` does not recognize anything: the bytes are random, so this box is not the secret. Doing the same for every box gives:

| Drop box | `file flag.jpg` says | Size | Verdict |
|---|---|---|---|
| `10.19.86.1:6666` | `data` | 107 KB | random bytes, decoy |
| `10.19.86.1:6669` | `JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16` | 180 KB | **fake**: JPEG header, then garbage |
| `10.19.86.1:9999` | `data` | 135 KB | decoy |
| `10.19.86.2:8081` | `data` | 161 KB | decoy |
| `10.19.86.2:8082` | `data` | 126 KB | decoy (141 requests for a total of 140) |
| `10.19.86.2:9997` | `data` | 143 KB | decoy |
| **`10.19.86.50:8686`** | `JPEG image data, JFIF standard 1.01, ..., baseline, precision 8, 1920x1080, components 3` | 487 KB | **real picture** |
| `10.19.86.50:8687` | `data` | 488 KB | decoy (same number of pieces as the real one, 543) |
| `192.168.1.100:8888` | `data` | 79 KB | decoy (89 requests for a total of 90) |
| `192.168.1.100:9998` | `data` | 89 KB | decoy |

Only two boxes make `file` say JPEG. The difference is in the details:

* `10.19.86.1:6669` stops after `segment length 16`. `file` found the JPEG header but nothing valid behind it, there is no size and no `baseline`. If you try to open it, the image viewer says it cannot read the file.
* `10.19.86.50:8686` continues with `baseline, precision 8, 1920x1080, components 3`. A complete picture with a size is the real one.

---

### 5. Open the picture

```bash
xdg-open flag.jpg
```

It is a Vice City sunset with the flag across the bottom:

`Securinets_fst{s3cr3ts_0v3r_http}`

---

## Key Takeaway

A file hidden in network traffic is often not one packet but many small requests, sent to different places and mixed with other traffic. Rebuild it with the information the protocol gives you (destination, `Index`) and never trust the frame order. Always check that the result is a real file, because data that decodes is not proof. And as the flag says, anything sent over plain HTTP can be read by whoever is listening on the wire.
