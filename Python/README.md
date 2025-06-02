# Ideas to implement
1. Ping Sweep / ICMP Scanner

Identify live hosts in the subnet before deeper scans.

    Use scapy or raw sockets.

    Handle firewalled hosts (send TCP SYN as backup).

    Optional: parallelize for speed using threading or asyncio.

2. Port Scanner (TCP SYN or Full Connect)

Scan specific or common ports on live hosts.

    SYN scan (half-open): stealthier.

    Full connect: easier, but noisier.

    Optional: Add UDP port scan support (slow, but useful).

3. Service Detection (Basic Banner Grabbing)

After port scan, connect to open ports and grab banners:

    socket.recv() for raw services (HTTP, FTP, etc.)

    Identify services and versions.

    Optional: include default creds check (e.g. for Telnet, FTP).

4. OS Fingerprinting (Basic TCP/IP Stack Analysis)

    TTL, Window Size, TCP Options (like Nmap does).

    Not as accurate as Nmap, but fun and educational to implement.

    scapy is helpful here.

5. MAC Vendor Lookup

Map MAC addresses to vendors (use OUI database).

    Can help identify device types (phones, printers, etc.).

    Use a local file or API like macvendors.com.

---

# Command

```bash
sudo $(which python3) main.py -ip 10.0.1.0/24
```

## Add
- threading to ping scan, it is slow