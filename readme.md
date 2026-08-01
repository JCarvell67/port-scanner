# port_scanner

A desktop TCP port scanner with a GUI. Built with Python and Tkinter. No external dependencies.

You point it at a host, give it a port range, and it tells you what's open.

> **Author:** LordCarvell

---

## Features

- **Multi-threaded scanning** - configurable thread count so it's actually fast
- **Live output log** - shows results as they come in, not at the end
- **Open ports table** - separate panel that lists every open port with its service name
- **Progress bar** - shows how far through the range you are
- **Stop button** - actually stops the scan mid-run
- **Export results** - save to JSON, CSV, or TXT once the scan finishes
- **Service detection** - recognises ~40 common ports (SSH, HTTP, RDP, MySQL, etc.)
- **DNS resolution** - accepts hostnames, not just IPs

---

## Requirements

- Python 3.9 or newer
- Nothing else. Tkinter comes with Python.

If Tkinter isn't available on your system (some Linux installs strip it out):

```
sudo apt install python3-tk
```

---

## Installation

Clone the repo or just download `main.py` on its own.

```
git clone https://github.com/LordCarvell/port-scanner.git
cd port-scanner
```

Run it:

```
python main.py
```

---

## How to Use

1. Enter a **host** - IP address or hostname
2. Set a **port range** - defaults to 1-1024 which covers most common services
3. Adjust **threads** if you want - higher is faster but noisier on the network
4. Adjust **timeout** if you're scanning something slow or over a bad connection
5. Click **scan**
6. Watch the output log. Open ports show up in green as they're found
7. The open ports panel on the right gives you a clean list when it's done
8. Click **save** to export results as JSON, CSV, or TXT

Click **stop** at any point to abort. The save button only appears if there are results.

---

## Export Formats

**JSON** - structured output with scan metadata included

```json
{
  "host": "192.168.1.1",
  "ip": "192.168.1.1",
  "port_range": [1, 1024],
  "scanned_at": "2026-03-21T14:30:00",
  "open_ports": [
    { "port": 22, "service": "SSH" },
    { "port": 80, "service": "HTTP" }
  ]
}
```

**CSV** - one row per port, includes host and timestamp columns. Easy to open in Excel or import elsewhere.

**TXT** - plain text summary. Readable without any tooling.

---

```
port-scanner/
├── main.py        # whole application, one file
└── README.md
```

---

## Known Issues

- **High thread counts can cause issues** - on some systems going above 500 threads causes socket errors. 150 is a reasonable default
- **Firewalls can cause false negatives** - a port that's filtered rather than closed will time out rather than refuse. You'll miss it unless your timeout is long enough
- **Windows firewall sometimes blocks outbound sockets** - if you're getting no results on a target you know has open ports, check your firewall settings
- **Not a replacement for nmap** - this is a basic TCP connect scanner. No UDP, no OS detection, no version detection. It just tells you if the port accepts a connection

---

## Roadmap

- Scan from a list of hosts
- Common port presets (top 100, well-known only, etc.)
- Ping check before scanning to confirm host is up

---

## Built With

- [Tkinter](https://docs.python.org/3/library/tkinter.html) - GUI (standard library)
- [socket](https://docs.python.org/3/library/socket.html) - TCP connections (standard library)
- [threading](https://docs.python.org/3/library/threading.html) - parallel scanning (standard library)

---

## Legal

Only scan hosts you own or have explicit permission to scan.  
Running this against systems without authorisation is illegal in most places.  
I'm not responsible for what you do with it.