#!/usr/bin/env python3
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║                         ONetWatch — v1.1                                   ║
# ║            Network MITM · ARP · Packet Sentinel for OWL OS                 ║
# ║                                                                             ║
# ║   Developer : khaled.s.haddad                                               ║
# ║   Website   : owlsec.org                                                    ║
# ║   Year      : 2026                                                          ║
# ║   License   : OWL OS Internal Tool                                          ║
# ╚══════════════════════════════════════════════════════════════════════════════╝

"""
ONetWatch v1.1 — Professional network monitoring tool.

Features
────────
• Real-time packet capture (ARP / TCP / UDP / ICMP / IP)
• ARP spoofing detection: IP-MAC mismatch, Gratuitous ARP,
  ARP flood, Gateway Impersonation
• Background DNS (PTR) resolver with TTL cache
• GeoIP lookup via ip-api.com (rate-limited, cached)
• All-device tracker (every IP seen, bandwidth per device)
• Protocol filter bar
• Alert flash + audio bell on MITM event
• Export results — user selects format AND save path (CSV / JSON / TXT)
• Beautiful dark terminal-style GUI
• Animated Help window

Usage (requires root / CAP_NET_RAW)
    sudo ONetWatch
"""

import csv
import json
import logging
import os
import platform
import socket
import sys
import threading
import time
import urllib.request
from collections import defaultdict, deque
from datetime import datetime

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk

# ── Suppress scapy noise ────────────────────────────────────────────────────
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
logging.getLogger("scapy.loading").setLevel(logging.ERROR)

try:
    from scapy.all import (ARP, Ether, IP, ICMP, TCP, UDP,
                           Raw, get_if_list, sniff)
except ImportError:
    print("[!] scapy not found.  Install with:  pip install scapy")
    sys.exit(1)

# ════════════════════════════════════════════════════════════════════════════
#  METADATA
# ════════════════════════════════════════════════════════════════════════════
APP_NAME  = "ONetWatch"
VERSION   = "v1.1"
DEVELOPER = "khaled.s.haddad"
WEBSITE   = "owlsec.org"
YEAR      = "2026"

# ════════════════════════════════════════════════════════════════════════════
#  THEME / PALETTE  (OWL OS dark terminal)
# ════════════════════════════════════════════════════════════════════════════
PRIMARY     = "#00FF00"    # matrix green
ACCENT      = "#FF3333"    # red — danger
CYAN        = "#39c5cf"
GOLD        = "#e3b341"
PURPLE      = "#c678dd"
BLUE        = "#3fb950"
BG          = "#000000"
BG2         = "#080808"
BG3         = "#0A0A0A"
BG4         = "#111111"
BG5         = "#050505"
SIDEBAR_BG  = "#0A0A0A"
STATUS_BG   = "#080808"
FONT        = "Consolas"
FONT_MONO   = "Courier New"

# ════════════════════════════════════════════════════════════════════════════
#  TUNABLES
# ════════════════════════════════════════════════════════════════════════════
ARP_RATE_WINDOW  = 5       # seconds
ARP_RATE_THRESH  = 20      # pkts/sec → flood
DNS_CACHE_TTL    = 300     # seconds
GEO_CACHE_TTL    = 3600    # seconds
MAX_TABLE_ROWS   = 5000    # packets kept in memory
MAX_TREE_ROWS    = 800     # rows visible in UI treeview
MAX_DEVICE_ROWS  = 400     # rows in ALL DEVICES tab
DNS_QUEUE_MAX    = 300
GEO_QUEUE_MAX    = 150
GEO_RATE_MAX     = 44      # ip-api.com: 45 req/min

# ════════════════════════════════════════════════════════════════════════════
#  PRIVATE IP DETECTION
# ════════════════════════════════════════════════════════════════════════════
_PRIVATE_PREFIXES = (
    "10.", "192.168.",
    "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
    "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "127.", "169.254.", "::1", "fe80",
)

def _is_private(ip: str) -> bool:
    return any(ip.startswith(p) for p in _PRIVATE_PREFIXES)

def _fmt_bytes(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1_048_576:
        return f"{n/1024:.1f} KB"
    if n < 1_073_741_824:
        return f"{n/1_048_576:.1f} MB"
    return f"{n/1_073_741_824:.2f} GB"

def _now_ts() -> str:
    return datetime.now().strftime("%H:%M:%S.%f")[:-3]

def _full_ts() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ════════════════════════════════════════════════════════════════════════════
#  DNS RESOLVER — background worker, TTL cache, non-blocking
# ════════════════════════════════════════════════════════════════════════════
class DNSCache:
    def __init__(self):
        self._cache: dict = {}
        self._lock  = threading.Lock()
        self._queue: deque = deque(maxlen=DNS_QUEUE_MAX)
        self._seen:  set   = set()
        threading.Thread(target=self._worker, daemon=True,
                          name="dns-resolver").start()

    def get(self, ip: str) -> str:
        with self._lock:
            entry = self._cache.get(ip)
        if entry:
            hostname, ts = entry
            if time.monotonic() - ts < DNS_CACHE_TTL:
                return hostname
        if ip not in self._seen:
            self._seen.add(ip)
            self._queue.append(ip)
        return ""

    def _worker(self):
        while True:
            if self._queue:
                ip = self._queue.popleft()
                try:
                    hostname = socket.gethostbyaddr(ip)[0]
                except Exception:
                    hostname = ip
                with self._lock:
                    self._cache[ip] = (hostname, time.monotonic())
                self._seen.discard(ip)
            else:
                time.sleep(0.15)


# ════════════════════════════════════════════════════════════════════════════
#  GEOIP — ip-api.com, rate-limited, TTL cache
# ════════════════════════════════════════════════════════════════════════════
class GeoIPCache:
    _LOCAL = {"country": "Local", "city": "", "isp": "Private Network"}
    _FAIL  = {"country": "?", "city": "", "isp": ""}

    def __init__(self):
        self._cache: dict  = {}
        self._lock         = threading.Lock()
        self._queue: deque = deque(maxlen=GEO_QUEUE_MAX)
        self._seen:  set   = set()
        self._rate_ts: deque = deque(maxlen=GEO_RATE_MAX + 5)
        threading.Thread(target=self._worker, daemon=True,
                          name="geo-resolver").start()

    def get(self, ip: str) -> dict:
        if _is_private(ip):
            return self._LOCAL
        with self._lock:
            entry = self._cache.get(ip)
        if entry:
            info, ts = entry
            if time.monotonic() - ts < GEO_CACHE_TTL:
                return info
        if ip not in self._seen:
            self._seen.add(ip)
            self._queue.append(ip)
        return {}

    def _worker(self):
        while True:
            if not self._queue:
                time.sleep(0.25)
                continue
            # rate-limit
            now = time.monotonic()
            self._rate_ts.append(now)
            while self._rate_ts and now - self._rate_ts[0] > 60:
                self._rate_ts.popleft()
            if len(self._rate_ts) > GEO_RATE_MAX:
                time.sleep(1.5)
                continue
            ip = self._queue.popleft()
            self._seen.discard(ip)
            if _is_private(ip):
                with self._lock:
                    self._cache[ip] = (self._LOCAL, time.monotonic())
                continue
            try:
                url = (f"http://ip-api.com/json/{ip}"
                       f"?fields=status,country,city,isp,org")
                with urllib.request.urlopen(url, timeout=4) as r:
                    data = json.loads(r.read().decode())
                if data.get("status") == "success":
                    info = {
                        "country": data.get("country", ""),
                        "city":    data.get("city", ""),
                        "isp":     data.get("isp", data.get("org", "")),
                    }
                else:
                    info = self._FAIL
            except Exception:
                info = self._FAIL
            with self._lock:
                self._cache[ip] = (info, time.monotonic())


# ════════════════════════════════════════════════════════════════════════════
#  ARP DETECTION ENGINE
# ════════════════════════════════════════════════════════════════════════════
class ARPEngine:
    """Detects IP-MAC mismatch, Gratuitous ARP, ARP flood,
       Gateway Impersonation."""

    def __init__(self):
        self._lock        = threading.Lock()
        self.ip_mac_table: dict  = {}
        self.arp_times:    deque = deque(maxlen=1000)
        self.gateway_ip:   str   = ""

    def set_gateway(self, gw: str):
        with self._lock:
            self.gateway_ip = gw.strip()

    def reset(self):
        with self._lock:
            self.ip_mac_table.clear()
            self.arp_times.clear()

    def analyze(self, pkt) -> list[str]:
        findings = []
        if not pkt.haslayer(ARP):
            return findings
        op      = pkt[ARP].op
        src_ip  = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc.lower()
        dst_ip  = pkt[ARP].pdst

        now = time.monotonic()
        with self._lock:
            self.arp_times.append(now)
            cutoff = now - ARP_RATE_WINDOW
            while self.arp_times and self.arp_times[0] < cutoff:
                self.arp_times.popleft()
            rate = len(self.arp_times) / ARP_RATE_WINDOW
            gw   = self.gateway_ip

        if rate > ARP_RATE_THRESH:
            findings.append(
                f"[FLOOD] ARP flood detected: {rate:.1f} pkt/s")

        # Gratuitous ARP — op is-at (2) and pdst == psrc
        if op == 2 and src_ip == dst_ip:
            findings.append(
                f"[GRATUITOUS] Unsolicited ARP reply from {src_ip}")

        if src_ip and src_mac:
            with self._lock:
                known = self.ip_mac_table.get(src_ip)
                if known is None:
                    self.ip_mac_table[src_ip] = src_mac
                elif known != src_mac:
                    findings.append(
                        f"[ARP-SPOOF] IP-MAC mismatch: {src_ip}  "
                        f"was [{known}]  now [{src_mac}]")
                    if gw and src_ip == gw:
                        findings.append(
                            f"[GATEWAY-HIJACK] Gateway {src_ip} "
                            f"impersonated!")
                    self.ip_mac_table[src_ip] = src_mac   # update baseline
        return findings


# ════════════════════════════════════════════════════════════════════════════
#  DEVICE TRACKER — every IP (not just ARP)
# ════════════════════════════════════════════════════════════════════════════
class DeviceTracker:
    def __init__(self):
        self._lock    = threading.Lock()
        self._devices: dict = {}
        # ip → {mac, bytes_out, bytes_in, pkts, first, last, dns, geo}

    def touch(self, src_ip: str, dst_ip: str,
              src_mac: str, size: int, ts: str):
        with self._lock:
            if src_ip and src_ip != "N/A":
                d = self._devices.setdefault(src_ip, {
                    "mac": src_mac, "bytes_out": 0, "bytes_in": 0,
                    "pkts": 0, "first": ts, "last": ts,
                    "dns": "", "geo": {}
                })
                d["bytes_out"] += size
                d["pkts"]      += 1
                d["last"]       = ts
                if src_mac and src_mac != "N/A":
                    d["mac"] = src_mac

            if dst_ip and dst_ip != "N/A":
                d2 = self._devices.setdefault(dst_ip, {
                    "mac": "", "bytes_out": 0, "bytes_in": 0,
                    "pkts": 0, "first": ts, "last": ts,
                    "dns": "", "geo": {}
                })
                d2["bytes_in"] += size
                d2["last"]      = ts

    def update_dns(self, ip: str, hostname: str):
        with self._lock:
            if ip in self._devices and hostname:
                self._devices[ip]["dns"] = hostname

    def update_geo(self, ip: str, geo: dict):
        with self._lock:
            if ip in self._devices and geo:
                self._devices[ip]["geo"] = geo

    def snapshot(self) -> list[dict]:
        with self._lock:
            items = list(self._devices.items())
        items.sort(key=lambda x: x[1]["pkts"], reverse=True)
        return [{"ip": ip, **info} for ip, info in items]

    def count(self) -> int:
        with self._lock:
            return len(self._devices)

    def reset(self):
        with self._lock:
            self._devices.clear()


# ════════════════════════════════════════════════════════════════════════════
#  EXPORT ENGINE — user chooses format + path
# ════════════════════════════════════════════════════════════════════════════
class ExportDialog(tk.Toplevel):
    """Modal dialog: user picks output format and save location."""

    FORMATS = ["JSON", "CSV", "TXT (Human-readable)"]

    def __init__(self, parent, packets: list, arp_records: dict,
                 device_tracker: DeviceTracker,
                 pkt_total: int, pkt_alerts: int):
        super().__init__(parent)
        self.title("Export Results")
        self.configure(bg=BG)
        self.resizable(False, False)
        self.grab_set()

        self._packets  = packets
        self._arp      = arp_records
        self._dt       = device_tracker
        self._total    = pkt_total
        self._alerts   = pkt_alerts

        self._fmt = tk.StringVar(value="JSON")

        # ── Header ──────────────────────────────────────────────
        hdr = tk.Frame(self, bg=BG3, pady=8)
        hdr.pack(fill="x")
        tk.Label(hdr, text="⬇  EXPORT RESULTS",
                 fg=PRIMARY, bg=BG3,
                 font=(FONT, 12, "bold")).pack(padx=16)
        tk.Label(hdr,
                 text=f"  {pkt_total} packets  ·  {pkt_alerts} alerts  "
                      f"·  {device_tracker.count()} devices",
                 fg="#666", bg=BG3,
                 font=(FONT, 8)).pack()

        # ── Format selection ─────────────────────────────────────
        body = tk.Frame(self, bg=BG, padx=24, pady=16)
        body.pack(fill="both", expand=True)

        tk.Label(body, text="Select export format:",
                 fg=PRIMARY, bg=BG,
                 font=(FONT, 10, "bold")).pack(anchor="w", pady=(0, 10))

        for fmt in self.FORMATS:
            colour = (PRIMARY if fmt == "JSON" else
                      CYAN    if fmt == "CSV"  else GOLD)
            rb = tk.Radiobutton(body,
                text=fmt, variable=self._fmt,
                value=fmt.split()[0],
                fg=colour, bg=BG,
                activeforeground=colour, activebackground=BG,
                selectcolor=BG4,
                font=(FONT, 10))
            rb.pack(anchor="w", padx=8, pady=3)

        # ── Description area ─────────────────────────────────────
        self._desc_lbl = tk.Label(body, text="",
            fg="#666", bg=BG, font=(FONT, 8),
            justify="left", wraplength=360)
        self._desc_lbl.pack(anchor="w", padx=8, pady=(6, 0))
        self._fmt.trace_add("write", self._update_desc)
        self._update_desc()

        # ── Buttons ──────────────────────────────────────────────
        btnf = tk.Frame(self, bg=BG3, pady=10)
        btnf.pack(fill="x")
        tk.Button(btnf, text="  CHOOSE PATH & SAVE  ",
                  bg=PRIMARY, fg=BG,
                  font=(FONT, 9, "bold"),
                  relief=tk.FLAT,
                  command=self._save).pack(side="left", padx=16)
        tk.Button(btnf, text="CANCEL",
                  bg=BG4, fg="#888",
                  font=(FONT, 9),
                  relief=tk.FLAT,
                  command=self.destroy).pack(side="left")

        self._center(parent)

    def _center(self, parent):
        self.update_idletasks()
        w, h = 420, 340
        px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

    def _update_desc(self, *_):
        fmt = self._fmt.get()
        msgs = {
            "JSON": "Full structured export: packets, ARP table,\n"
                    "device list, stats. Ideal for post-analysis.",
            "CSV":  "Flat spreadsheet export of captured packets.\n"
                    "Opens in Excel / LibreOffice Calc.",
            "TXT":  "Human-readable report with headers,\n"
                    "summary block, alerts list and device table.",
        }
        self._desc_lbl.config(text=msgs.get(fmt, ""))

    def _save(self):
        fmt = self._fmt.get()
        exts  = {"JSON": ".json", "CSV": ".csv",  "TXT": ".txt"}
        types = {
            "JSON": [("JSON files", "*.json"), ("All files", "*.*")],
            "CSV":  [("CSV files",  "*.csv"),  ("All files", "*.*")],
            "TXT":  [("Text files", "*.txt"),  ("All files", "*.*")],
        }
        init = f"onetwatch_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        path = filedialog.asksaveasfilename(
            parent=self,
            defaultextension=exts[fmt],
            filetypes=types[fmt],
            initialfile=init + exts[fmt],
            title="Save ONetWatch Report")
        if not path:
            return

        try:
            if fmt == "JSON":
                self._write_json(path)
            elif fmt == "CSV":
                self._write_csv(path)
            else:
                self._write_txt(path)
            messagebox.showinfo(
                "Export successful",
                f"Report saved to:\n{path}", parent=self)
            self.destroy()
        except Exception as exc:
            messagebox.showerror(
                "Export failed", str(exc), parent=self)

    # ── writers ─────────────────────────────────────────────────
    def _write_json(self, path: str):
        payload = {
            "tool":      APP_NAME,
            "version":   VERSION,
            "exported":  _full_ts(),
            "stats": {
                "total_packets": self._total,
                "alerts":        self._alerts,
                "unique_devices": self._dt.count(),
            },
            "packets":      self._packets,
            "arp_table":    self._arp,
            "all_devices":  self._dt.snapshot(),
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

    def _write_csv(self, path: str):
        if not self._packets:
            raise ValueError("No packets to export.")
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f, fieldnames=list(self._packets[0].keys()))
            writer.writeheader()
            writer.writerows(self._packets)

    def _write_txt(self, path: str):
        sep  = "═" * 70
        sep2 = "─" * 70
        lines = [
            sep,
            f"  ONetWatch {VERSION}  —  Network Capture Report",
            f"  Exported : {_full_ts()}",
            f"  Site     : {WEBSITE}  ·  Developer: {DEVELOPER}",
            sep,
            "",
            "  SUMMARY",
            sep2,
            f"  Total packets   : {self._total}",
            f"  Security alerts : {self._alerts}",
            f"  Unique devices  : {self._dt.count()}",
            "",
            "  ALERTS",
            sep2,
        ]
        alert_pkts = [p for p in self._packets if p.get("alert")]
        if alert_pkts:
            for p in alert_pkts:
                lines.append(
                    f"  [{p['time']}] {p['alert']}")
                lines.append(
                    f"    Src: {p['src_ip']}  MAC: {p['src_mac']}")
        else:
            lines.append("  No alerts recorded.")

        lines += ["", "  ALL DEVICES", sep2]
        for d in self._dt.snapshot()[:200]:
            geo = d.get("geo", {})
            geo_str = (f"{geo.get('city','')} {geo.get('country','')}"
                       f" [{geo.get('isp','')}]").strip()
            lines.append(
                f"  {d['ip']:<18}  {d.get('dns',''):<30}  "
                f"{_fmt_bytes(d.get('bytes_out',0)):>8} out  "
                f"{_fmt_bytes(d.get('bytes_in',0)):>8} in  "
                f"{geo_str}")

        lines += ["", "  PACKET LOG (first 2000)", sep2]
        for p in self._packets[:2000]:
            lines.append(
                f"  {p['time']}  {p['proto']:<5}  "
                f"{p['src_ip']:<18} → {p['dst_ip']:<18}  "
                f"{p.get('payload','')}")
        lines += ["", sep]

        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))


# ════════════════════════════════════════════════════════════════════════════
#  HELP WINDOW — animated, tabbed, rich content
# ════════════════════════════════════════════════════════════════════════════
class HelpWindow(tk.Toplevel):
    _SECTIONS = {
        "Quick Start": (CYAN, """
STEP 1 — Select your network interface from the dropdown.
         On Linux this is usually  eth0  or  wlan0.
         Requires root / CAP_NET_RAW to capture packets.

STEP 2 — Enter the Gateway IP (your router's address).
         Default is 192.168.1.1 — change if your subnet differs.
         This is used to detect Gateway Impersonation attacks.

STEP 3 — Toggle DNS Resolve and GeoIP Lookup if desired.
         Both run in background threads and never block capture.

STEP 4 — Click  START CAPTURE  to begin monitoring.
         Use the protocol filter bar to narrow the live view.

STEP 5 — When done, click  EXPORT  to save results.
         You will choose the format (JSON / CSV / TXT) and path.
"""),
        "Detection Engine": (ACCENT, """
ONetWatch monitors every packet passing through the selected
interface and applies the following detection rules in real-time:

[ARP-SPOOF]       IP-MAC Mismatch
  → A known IP is now advertising a different MAC address.
    Classic ARP poisoning / MITM indicator.

[GRATUITOUS ARP]  Unsolicited is-at reply
  → A host broadcasts its MAC without being asked.
    Legitimate in some boot sequences, suspicious otherwise.

[FLOOD]           ARP flood  (> 20 ARP/sec over 5 s)
  → Mass ARP requests or replies — scanner or DoS tool.

[GATEWAY-HIJACK]  Gateway MAC change
  → The gateway IP changed its MAC. All traffic on the subnet
    may be intercepted. Critical alert.

On any detection, the UI flashes red, a bell sounds, and the
event is logged to the ALERTS tab with full packet context.
"""),
        "Tabs & Views": (GOLD, """
PACKETS tab
  Live scrolling packet table.  Click any row to see:
    · Source / destination hostname (DNS resolved)
    · GeoIP — country, city, ISP
    · Protocol ports
    · Alert detail

ARP TABLE tab
  Trusted IP→MAC baseline built during capture.
  Rows turn red when a mismatch is detected.
  Use "Clear Table" to reset the baseline.

ALERTS tab
  Chronological log of all security events.
  Each entry shows timestamp, alert type, src IP, MAC.

ALL DEVICES tab
  Every unique IP seen (ARP + TCP + UDP + ICMP).
  Columns: Hostname, GeoIP, MAC, Bytes Sent, Bytes Received,
           Packet count, Last seen timestamp.
  Auto-refreshes every 2 seconds.

PACKET DETAIL (bottom panel)
  Selecting a row shows enriched analysis including
  hostname and GeoIP — fetched in background.
"""),
        "Export": (PRIMARY, """
Click  EXPORT  in the control panel to open the export dialog.

You will choose:

  [JSON]  Full structured export
          Includes packets, ARP table, device list and stats.
          Best for post-analysis scripts or SIEM import.

  [CSV]   Flat spreadsheet of captured packets.
          Opens directly in Excel or LibreOffice Calc.

  [TXT]   Human-readable report with summary, alert list,
          device bandwidth table and packet log.

After choosing format, a file-save dialog lets you pick
the exact folder and filename — no hidden default paths.

Exports include a timestamp in the filename suggestion
so you never overwrite previous sessions.
"""),
        "Keyboard & Tips": (PURPLE, f"""
Keyboard shortcuts
  There are no keyboard shortcuts defined yet — use the mouse.
  (Future version will add Ctrl+S to export, Ctrl+C to clear.)

Performance tips
  · On busy networks, the packet buffer holds {MAX_TABLE_ROWS} packets.
    Older packets are discarded from memory (already visible in log).
  · Disable GeoIP on high-traffic links (saves bandwidth / API rate).
  · DNS resolve is always local (no external call) — safe to keep on.
  · The device table auto-refreshes every 2 s; click Refresh manually
    if you want an immediate update.

Privilege requirement
  ONetWatch needs root or CAP_NET_RAW to open raw sockets.
  On OWL OS:  sudo ONetWatch
  or grant capability:  setcap cap_net_raw+ep python3

About
  Tool  : {APP_NAME} {VERSION}
  Author: {DEVELOPER}
  Site  : {WEBSITE}
  Year  : {YEAR}
"""),
    }

    def __init__(self, parent):
        super().__init__(parent)
        self.title(f"ONetWatch {VERSION} — Help")
        self.configure(bg=BG)
        self.resizable(True, True)
        self.minsize(640, 520)
        self._build()
        self._center(parent)
        self.grab_set()

    def _center(self, parent):
        self.update_idletasks()
        w, h = 720, 580
        px = parent.winfo_rootx() + (parent.winfo_width()  - w) // 2
        py = parent.winfo_rooty() + (parent.winfo_height() - h) // 2
        self.geometry(f"{w}x{h}+{px}+{py}")

    def _build(self):
        # Top banner
        banner = tk.Frame(self, bg=BG3, pady=0)
        banner.pack(fill="x")
        self._owl_lbl = tk.Label(banner,
            text="🦉  ONetWatch — Reference Manual",
            fg=PRIMARY, bg=BG3,
            font=(FONT, 14, "bold"))
        self._owl_lbl.pack(side="left", padx=16, pady=10)
        tk.Label(banner,
            text=f"{VERSION}  ·  {WEBSITE}",
            fg="#444", bg=BG3,
            font=(FONT, 8)).pack(side="right", padx=16)

        # Two-column layout: section list + content
        body = tk.Frame(self, bg=BG)
        body.pack(fill="both", expand=True)

        # Left — section list
        nav = tk.Frame(body, bg=BG3, width=170)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Label(nav, text=" SECTIONS",
                 fg="#555", bg=BG3,
                 font=(FONT, 8, "bold")).pack(
                     anchor="w", padx=8, pady=(8, 4))
        self._nav_btns = []
        for i, section in enumerate(self._SECTIONS.keys()):
            b = tk.Button(nav,
                text=f"  {section}",
                bg=BG3, fg=PRIMARY,
                relief=tk.FLAT, anchor="w",
                font=(FONT, 9),
                command=lambda s=section: self._show_section(s))
            b.pack(fill="x", padx=4, pady=1)
            self._nav_btns.append(b)

        # Right — content
        right = tk.Frame(body, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        self._content_title = tk.Label(right, text="",
            fg=PRIMARY, bg=BG,
            font=(FONT, 11, "bold"), anchor="w")
        self._content_title.pack(fill="x", padx=14, pady=(10, 4))

        self._content = scrolledtext.ScrolledText(right,
            bg=BG2, fg=PRIMARY,
            font=(FONT_MONO, 10),
            padx=14, pady=10,
            borderwidth=0,
            wrap="word",
            state="disabled")
        self._content.pack(fill="both", expand=True,
                           padx=8, pady=(0, 8))

        # Footer
        foot = tk.Frame(self, bg=BG4, pady=6)
        foot.pack(fill="x")
        tk.Button(foot, text="  CLOSE  ",
                  bg=PRIMARY, fg=BG,
                  font=(FONT, 9, "bold"),
                  relief=tk.FLAT,
                  command=self.destroy).pack(side="right", padx=14)

        # Show first section
        first = list(self._SECTIONS.keys())[0]
        self._show_section(first)

    def _show_section(self, section: str):
        colour, text = self._SECTIONS[section]
        self._content_title.config(text=f"  ◈  {section}", fg=colour)
        self._content.config(state="normal")
        self._content.delete(1.0, tk.END)
        self._content.config(fg=colour)
        self._content.insert(tk.END, text.strip())
        self._content.config(state="disabled")
        # highlight active nav button
        for b in self._nav_btns:
            name = b.cget("text").strip()
            if name == section:
                b.config(bg="#003300", fg=colour)
            else:
                b.config(bg=BG3, fg=PRIMARY)


# ════════════════════════════════════════════════════════════════════════════
#  MAIN APPLICATION
# ════════════════════════════════════════════════════════════════════════════
class ONetWatchApp(tk.Tk):

    def __init__(self):
        super().__init__()

        # ── State ───────────────────────────────────────────────
        self.capturing      = False
        self.sniffer_thread = None
        self.table_packets: list  = []
        self._packets_lock  = threading.Lock()
        self.ip_mac_map: dict     = {}
        self.arp_engine     = ARPEngine()
        self.device_tracker = DeviceTracker()
        self.dns_cache      = DNSCache()
        self.geo_cache      = GeoIPCache()

        # Stats
        self._stats_lock  = threading.Lock()
        self._pkt_total   = 0
        self._pkt_alerts  = 0
        self._pkt_window  = deque(maxlen=2000)
        self._proto_count: defaultdict = defaultdict(int)

        # ARP baseline records
        self._arp_records: dict = {}

        # Alert flash state
        self._alert_active = False
        self._flash_count  = 0

        # ── Window setup ────────────────────────────────────────
        self.tk.call("tk", "scaling", 1.0)
        self.title(f"🦉  {APP_NAME} {VERSION}  ·  {WEBSITE}")
        self.configure(bg=BG)

        if platform.system() == "Windows":
            self.state("zoomed")
        else:
            try:
                self.attributes("-zoomed", True)
            except Exception:
                self.geometry("1280x800")

        self.minsize(1100, 650)
        self.protocol("WM_DELETE_WINDOW", self.safe_exit)

        self._build_style()
        self._build_ui()
        self._detect_interfaces()
        self._tick_stats()
        self._tick_devices()

    # ════════════════════════════════════════════════════════════
    #  STYLE
    # ════════════════════════════════════════════════════════════
    def _build_style(self):
        s = ttk.Style()
        try:
            s.theme_use("clam")
        except Exception:
            pass
        s.configure("Treeview",
            background=BG, foreground=PRIMARY,
            fieldbackground=BG, rowheight=22, borderwidth=0,
            relief="flat")
        s.configure("Treeview.Heading",
            background=BG3, foreground=PRIMARY,
            font=(FONT, 9, "bold"), borderwidth=0, relief="flat")
        s.map("Treeview",
            background=[("selected", "#003300")],
            foreground=[("selected", "#ffffff")])
        s.configure("TNotebook",
            background=BG, borderwidth=0)
        s.configure("TNotebook.Tab",
            background=BG3, foreground=PRIMARY,
            font=(FONT, 9, "bold"), padding=[12, 5])
        s.map("TNotebook.Tab",
            background=[("selected", "#002200")],
            foreground=[("selected", PRIMARY)])
        s.configure("Vertical.TScrollbar",
            background=BG3, troughcolor=BG,
            arrowcolor=PRIMARY, borderwidth=0)

    # ════════════════════════════════════════════════════════════
    #  UI
    # ════════════════════════════════════════════════════════════
    def _build_ui(self):
        self._build_header()
        self._build_dashboard()
        self._build_filter_bar()
        self._build_alert_banner()
        self._build_main_panes()
        self._build_status_bar()

    # ── Header ───────────────────────────────────────────────
    def _build_header(self):
        hdr = tk.Frame(self, bg=BG3, pady=0)
        hdr.pack(fill="x")

        tk.Label(hdr, text="🦉",
                 fg=PRIMARY, bg=BG3,
                 font=(FONT, 18)).pack(side="left", padx=(12, 2), pady=6)
        tk.Label(hdr, text=APP_NAME,
                 fg=PRIMARY, bg=BG3,
                 font=(FONT, 16, "bold")).pack(side="left", pady=8)
        tk.Label(hdr,
                 text=f"  Network MITM · ARP · Packet Sentinel  ·  {VERSION}",
                 fg="#444", bg=BG3,
                 font=(FONT, 9)).pack(side="left", pady=10)

        # Right-side header buttons
        for txt, cmd, fg_, bg_ in [
            ("  HELP  ",  self.show_help,  BG, PRIMARY),
            ("  EXIT  ",  self.safe_exit,  BG, ACCENT),
        ]:
            tk.Button(hdr, text=txt, command=cmd,
                      fg=fg_, bg=bg_,
                      relief=tk.FLAT,
                      font=(FONT, 9, "bold"),
                      padx=4).pack(
                          side="right", padx=6, pady=8)

        # Thin accent line
        tk.Frame(self, bg="#003300", height=1).pack(fill="x")

    # ── Stats dashboard ──────────────────────────────────────
    def _build_dashboard(self):
        dash = tk.Frame(self, bg=BG3, height=58)
        dash.pack(fill="x")
        dash.pack_propagate(False)
        self._stat_lbl: dict = {}
        cards = [
            ("PACKETS",   "total",   PRIMARY),
            ("PKT/SEC",   "rate",    CYAN),
            ("ALERTS",    "alerts",  ACCENT),
            ("ALL IPs",   "devices", GOLD),
            ("ARP",       "arp",     PURPLE),
            ("TCP",       "tcp",     BLUE),
            ("UDP",       "udp",     "#d29922"),
            ("ICMP",      "icmp",    "#e06c75"),
            ("UPTIME",    "uptime",  "#888888"),
        ]
        for lbl, key, col in cards:
            card = tk.Frame(dash, bg=BG3)
            card.pack(side="left", expand=True, fill="both", padx=1)
            tk.Label(card, text=lbl,
                     font=(FONT, 7), fg="#555", bg=BG3).pack(pady=(5, 0))
            l = tk.Label(card, text="0",
                         font=(FONT, 12, "bold"), fg=col, bg=BG3)
            l.pack()
            self._stat_lbl[key] = l
        self._capture_start: float = 0.0

    # ── Protocol filter bar ──────────────────────────────────
    def _build_filter_bar(self):
        fbar = tk.Frame(self, bg=BG5, height=28)
        fbar.pack(fill="x")
        fbar.pack_propagate(False)
        tk.Label(fbar, text=" FILTER:",
                 fg="#555", bg=BG5,
                 font=(FONT, 8, "bold")).pack(side="left", padx=8)
        self._proto_filter = tk.StringVar(value="ALL")
        protos = [
            ("ALL",  PRIMARY),
            ("ARP",  PURPLE),
            ("TCP",  BLUE),
            ("UDP",  CYAN),
            ("ICMP", "#e06c75"),
            ("Other","#888"),
        ]
        for p, col in protos:
            tk.Radiobutton(fbar, text=p,
                variable=self._proto_filter, value=p,
                font=(FONT, 8), fg=col, bg=BG5,
                activeforeground=col, activebackground=BG5,
                selectcolor=BG,
                command=self._apply_filter
            ).pack(side="left", padx=5)

        # right side: clear + export
        tk.Button(fbar, text="CLEAR",
                  bg=BG4, fg="#888",
                  relief=tk.FLAT,
                  font=(FONT, 8),
                  command=self._clear_all).pack(
                      side="right", padx=8)
        tk.Button(fbar, text="⬇ EXPORT",
                  bg="#1a3300", fg=PRIMARY,
                  relief=tk.FLAT,
                  font=(FONT, 8, "bold"),
                  command=self._open_export).pack(
                      side="right", padx=4)

    # ── Alert banner ─────────────────────────────────────────
    def _build_alert_banner(self):
        self._alert_banner = tk.Label(
            self,
            text="⚠   MITM / ARP ATTACK DETECTED   ⚠",
            font=(FONT, 10, "bold"),
            fg="#ff6b6b", bg="#2d0f0f")

    # ── Main paned area (sidebar + notebook) ─────────────────
    def _build_main_panes(self):
        paned = tk.PanedWindow(self, orient=tk.HORIZONTAL,
                               bg=BG, bd=0, sashwidth=4,
                               sashrelief=tk.FLAT)
        paned.pack(expand=True, fill="both", pady=(2, 0))

        self._build_sidebar(paned)
        self._build_notebook(paned)

    # ── Sidebar (control panel) ──────────────────────────────
    def _build_sidebar(self, paned):
        left = tk.Frame(paned, bg=SIDEBAR_BG)
        paned.add(left, minsize=240)

        def _section_label(text, pady_top=12):
            tk.Label(left, text=text,
                     fg="#555", bg=SIDEBAR_BG,
                     font=(FONT, 7, "bold")).pack(
                         anchor="w", padx=12, pady=(pady_top, 2))

        tk.Label(left, text="◈ CONTROL",
                 fg=PRIMARY, bg=SIDEBAR_BG,
                 font=(FONT, 11, "bold")).pack(
                     anchor="w", padx=12, pady=(10, 4))
        tk.Frame(left, bg="#003300", height=1).pack(
            fill="x", padx=8, pady=2)

        # Interface
        _section_label("INTERFACE")
        self.iface_combo = ttk.Combobox(left, state="readonly",
                                         font=(FONT, 9))
        self.iface_combo.pack(fill="x", padx=12)

        # Gateway
        _section_label("GATEWAY IP")
        self.gw_entry = tk.Entry(left, bg=BG4, fg=PRIMARY,
                                  insertbackground=PRIMARY,
                                  font=(FONT, 9), relief=tk.FLAT,
                                  highlightthickness=1,
                                  highlightbackground="#003300")
        self.gw_entry.insert(0, "192.168.1.1")
        self.gw_entry.pack(fill="x", padx=12, ipady=3)

        # Buttons
        tk.Frame(left, bg=SIDEBAR_BG, height=8).pack()
        self.start_btn = tk.Button(left,
            text="▶  START CAPTURE",
            bg=PRIMARY, fg=BG,
            font=(FONT, 10, "bold"), relief=tk.FLAT,
            command=self.start_capture)
        self.start_btn.pack(fill="x", padx=12, pady=(0, 3), ipady=4)

        self.stop_btn = tk.Button(left,
            text="■  STOP",
            bg=ACCENT, fg=BG,
            font=(FONT, 10, "bold"), relief=tk.FLAT,
            state="disabled",
            command=self.stop_capture)
        self.stop_btn.pack(fill="x", padx=12, ipady=3)

        self.load_btn = tk.Button(left,
            text="📂  LOAD PCAP",
            bg="#1a3300", fg=PRIMARY,
            font=(FONT, 9, "bold"), relief=tk.FLAT,
            command=self.load_pcap)
        self.load_btn.pack(fill="x", padx=12, pady=(3, 0), ipady=3)

        tk.Frame(left, bg="#222", height=1).pack(
            fill="x", padx=8, pady=8)

        # Options
        _section_label("OPTIONS", pady_top=0)
        self._dns_enabled = tk.BooleanVar(value=True)
        self._geo_enabled = tk.BooleanVar(value=False)  # v1.1: off by default (no external lookup)
        self._sound_enabled = tk.BooleanVar(value=True)
        self._autoscroll   = tk.BooleanVar(value=True)

        for text, var, col in [
            ("DNS Resolve",  self._dns_enabled,  CYAN),
            ("GeoIP Lookup", self._geo_enabled,   GOLD),
            ("Sound Alerts", self._sound_enabled, PURPLE),
            ("Auto-scroll",  self._autoscroll,    BLUE),
        ]:
            tk.Checkbutton(left, text=f"  {text}",
                variable=var,
                fg=col, bg=SIDEBAR_BG,
                activeforeground=col,
                activebackground=SIDEBAR_BG,
                selectcolor=BG,
                font=(FONT, 8)).pack(anchor="w", padx=12, pady=1)

        tk.Frame(left, bg="#222", height=1).pack(
            fill="x", padx=8, pady=8)

        # ARP device sidebar list
        _section_label("ARP DEVICES", pady_top=0)
        list_frame = tk.Frame(left, bg=SIDEBAR_BG)
        list_frame.pack(fill="both", expand=True, padx=12, pady=(0, 4))
        scrollbar = tk.Scrollbar(list_frame, bg=BG3,
                                   troughcolor=BG, width=8)
        scrollbar.pack(side="right", fill="y")
        self.dev_list = tk.Listbox(list_frame,
            bg=BG5, fg=PRIMARY,
            font=(FONT, 8), borderwidth=0,
            selectbackground="#003300",
            yscrollcommand=scrollbar.set)
        self.dev_list.pack(side="left", fill="both", expand=True)
        scrollbar.config(command=self.dev_list.yview)

    # ── Notebook (main content area) ─────────────────────────
    def _build_notebook(self, paned):
        right = tk.Frame(paned, bg=BG)
        paned.add(right, minsize=680)

        nb = ttk.Notebook(right)
        nb.pack(expand=True, fill="both", padx=6, pady=(4, 0))

        self._build_tab_packets(nb)
        self._build_tab_arp(nb)
        self._build_tab_alerts(nb)
        self._build_tab_devices(nb)

        # Details panel (bottom)
        det_hdr = tk.Frame(right, bg=BG3, pady=2)
        det_hdr.pack(fill="x", padx=6)
        tk.Label(det_hdr, text=" ◈ PACKET DETAIL",
                 fg="#555", bg=BG3,
                 font=(FONT, 8, "bold")).pack(side="left", padx=8)
        tk.Button(det_hdr, text="clear",
                  bg=BG3, fg="#333",
                  relief=tk.FLAT, font=(FONT, 7),
                  command=lambda: self.details.delete(1.0, tk.END)
                  ).pack(side="right", padx=6)
        self.details = scrolledtext.ScrolledText(right,
            height=7, bg=BG2, fg=PRIMARY,
            font=(FONT_MONO, 9), borderwidth=0,
            wrap="word")
        self.details.pack(fill="x", padx=6, pady=(0, 6))

    def _build_tab_packets(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  PACKETS  ")
        columns = ("Time", "Src IP", "Dst IP",
                   "Src MAC", "Proto", "Size", "Info", "Alert")
        self.tree = ttk.Treeview(frame,
            columns=columns, show="headings",
            selectmode="browse")
        widths = [82, 130, 130, 140, 60, 55, 180, 200]
        for col, w in zip(columns, widths):
            self.tree.heading(col, text=col,
                command=lambda c=col: self._sort_tree(c))
            self.tree.column(col, width=w, anchor="w", minwidth=40)
        self.tree.tag_configure("alert",
            background="#330000", foreground=ACCENT)
        self.tree.tag_configure("arp",  foreground=PURPLE)
        self.tree.tag_configure("tcp",  foreground=BLUE)
        self.tree.tag_configure("udp",  foreground=CYAN)
        self.tree.tag_configure("icmp", foreground="#e06c75")

        vsb = ttk.Scrollbar(frame, orient="vertical",
                              command=self.tree.yview)
        hsb = ttk.Scrollbar(frame, orient="horizontal",
                              command=self.tree.xview)
        self.tree.configure(yscrollcommand=vsb.set,
                             xscrollcommand=hsb.set)
        hsb.pack(side="bottom", fill="x")
        vsb.pack(side="right",  fill="y")
        self.tree.pack(expand=True, fill="both")
        self.tree.bind("<<TreeviewSelect>>", self._on_row_select)

    def _build_tab_arp(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  ARP TABLE  ")
        hdr = tk.Frame(frame, bg=BG3)
        hdr.pack(fill="x")
        tk.Label(hdr, text="  ◈ Trusted ARP Baseline  (IP → MAC)",
                 fg=GOLD, bg=BG3,
                 font=(FONT, 9, "bold"), padx=8).pack(
                     side="left", anchor="w", pady=4)
        tk.Button(hdr, text="Clear Table",
                  bg=BG4, fg=PRIMARY, font=(FONT, 8),
                  relief=tk.FLAT,
                  command=self._clear_arp_table).pack(
                      side="right", padx=8, pady=3)
        cols = [
            ("ip",     "IP Address", 135),
            ("mac",    "MAC Address",155),
            ("first",  "First Seen",  90),
            ("last",   "Last Seen",   90),
            ("count",  "ARP#",        55),
            ("status", "Status",     120),
        ]
        self.arp_tree = ttk.Treeview(frame,
            columns=[c[0] for c in cols],
            show="headings")
        for c, h, w in cols:
            self.arp_tree.heading(c, text=h)
            self.arp_tree.column(c, width=w, anchor="w")
        self.arp_tree.tag_configure("suspicious",
            background="#330000", foreground=ACCENT)
        self.arp_tree.tag_configure("trusted", foreground=BLUE)
        vsb = ttk.Scrollbar(frame, orient="vertical",
                              command=self.arp_tree.yview)
        self.arp_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.arp_tree.pack(fill="both", expand=True)

    def _build_tab_alerts(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  ALERTS  ")
        hdr = tk.Frame(frame, bg=BG3)
        hdr.pack(fill="x")
        self._alert_count_lbl = tk.Label(hdr, text="  0 alerts",
            fg=ACCENT, bg=BG3,
            font=(FONT, 9, "bold"), padx=8)
        self._alert_count_lbl.pack(side="left", pady=4)
        tk.Button(hdr, text="Clear",
                  bg=BG4, fg="#888", font=(FONT, 8),
                  relief=tk.FLAT,
                  command=self._clear_alerts).pack(
                      side="right", padx=8, pady=3)
        self._alert_log = scrolledtext.ScrolledText(frame,
            bg=BG2, fg=ACCENT,
            font=(FONT_MONO, 9),
            borderwidth=0,
            state="disabled")
        self._alert_log.pack(fill="both", expand=True)

    def _build_tab_devices(self, nb):
        frame = tk.Frame(nb, bg=BG)
        nb.add(frame, text="  ALL DEVICES  ")
        hdr = tk.Frame(frame, bg=BG3)
        hdr.pack(fill="x")
        tk.Label(hdr,
                 text="  ◈ All Observed IPs  (ARP + TCP + UDP + ICMP)",
                 fg=GOLD, bg=BG3,
                 font=(FONT, 9, "bold"), padx=8).pack(
                     side="left", anchor="w", pady=4)
        tk.Button(hdr, text="↺ Refresh",
                  bg=BG4, fg=PRIMARY, font=(FONT, 8),
                  relief=tk.FLAT,
                  command=self._refresh_device_tab).pack(
                      side="right", padx=8, pady=3)
        cols = [
            ("ip",        "IP Address",   130),
            ("dns",       "Hostname",     175),
            ("geo",       "Country / ISP",185),
            ("mac",       "MAC",          145),
            ("bytes_out", "→ Sent",        80),
            ("bytes_in",  "← Recv",        80),
            ("pkts",      "Pkts",          55),
            ("last",      "Last Seen",     75),
        ]
        self.dev_tree = ttk.Treeview(frame,
            columns=[c[0] for c in cols],
            show="headings")
        for c, h, w in cols:
            self.dev_tree.heading(c, text=h,
                command=lambda col=c: self._sort_dev_tree(col))
            self.dev_tree.column(c, width=w, anchor="w")
        self.dev_tree.tag_configure("external", foreground=CYAN)
        self.dev_tree.tag_configure("local",    foreground=PRIMARY)
        self.dev_tree.tag_configure("gateway",  foreground=GOLD)
        vsb = ttk.Scrollbar(frame, orient="vertical",
                              command=self.dev_tree.yview)
        self.dev_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        self.dev_tree.pack(fill="both", expand=True)

    # ── Status bar ───────────────────────────────────────────
    def _build_status_bar(self):
        bar = tk.Frame(self, bg=STATUS_BG, pady=1)
        bar.pack(side="bottom", fill="x")
        self.status_bar = tk.Label(bar,
            text="  Ready — select interface and click START CAPTURE",
            bg=STATUS_BG, fg="#555",
            font=(FONT, 8), anchor="w")
        self.status_bar.pack(side="left", fill="x", expand=True)
        tk.Label(bar,
            text=f"  {WEBSITE}  ·  {DEVELOPER}  ·  {APP_NAME} {VERSION}  ·  © {YEAR}  ",
            bg=STATUS_BG, fg="#333",
            font=(FONT, 7)).pack(side="right")

    # ════════════════════════════════════════════════════════════
    #  INTERFACE DETECTION
    # ════════════════════════════════════════════════════════════
    def _detect_interfaces(self):
        try:
            # Include lo for localhost sandbox testing (v1.1)
            ifs = list(get_if_list()) or ["lo"]
            self.iface_combo["values"] = ifs
            # Prefer non-loopback if available, else lo
            pick = 0
            for i, name in enumerate(ifs):
                if "lo" not in name.lower():
                    pick = i
                    break
            if ifs:
                self.iface_combo.current(pick)
        except Exception:
            self.iface_combo["values"] = ["lo"]
            self.iface_combo.current(0)

    # ════════════════════════════════════════════════════════════
    #  CAPTURE CONTROL
    # ════════════════════════════════════════════════════════════
    def start_capture(self):
        gw = self.gw_entry.get().strip()
        iface = self.iface_combo.get().strip()
        if not iface:
            messagebox.showwarning(
                "No Interface",
                "Please select a network interface.", parent=self)
            return
        self.arp_engine.set_gateway(gw)
        self.capturing = True
        self._capture_start = time.monotonic()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.status_bar.config(
            text=f"  Capturing on [{iface}]  ·  Gateway: {gw or 'not set'}",
            fg=PRIMARY)
        self.sniffer_thread = threading.Thread(
            target=self._run_sniffer,
            args=(iface,), daemon=True,
            name="packet-sniffer")
        self.sniffer_thread.start()

    def stop_capture(self):
        self.capturing = False
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.status_bar.config(
            text="  Capture stopped — use EXPORT to save results",
            fg=GOLD)

    def _run_sniffer(self, iface: str):
        try:
            sniff(iface=iface,
                  prn=self._process_packet,
                  store=False,
                  stop_filter=lambda _: not self.capturing)
        except Exception as exc:
            self.after(0, self.status_bar.config,
                       {"text": f"  Sniffer error: {exc}",
                        "fg": ACCENT})

    # ════════════════════════════════════════════════════════════
    #  PACKET PROCESSING
    # ════════════════════════════════════════════════════════════
    def _process_packet(self, pkt):
        ts       = _now_ts()
        src_ip   = dst_ip = "N/A"
        proto    = "Other"
        info     = ""
        alerts   = []
        src_mac  = (pkt[Ether].src if pkt.haslayer(Ether) else "N/A")
        size     = len(pkt)

        # ── Layer decode ────────────────────────────────────
        if pkt.haslayer(ARP):
            proto  = "ARP"
            src_ip = pkt[ARP].psrc
            dst_ip = pkt[ARP].pdst
            op_str = "who-has" if pkt[ARP].op == 1 else "is-at"
            info   = f"ARP {op_str}"
            alerts = self.arp_engine.analyze(pkt)
            with self._packets_lock:
                changed = (src_ip not in self.ip_mac_map
                           or self.ip_mac_map[src_ip] != src_mac)
                self.ip_mac_map[src_ip] = src_mac
            if changed:
                self.after(0, self._update_dev_ui)
            self.after(0, self._update_arp_record,
                       src_ip, src_mac, ts, bool(alerts))

        elif pkt.haslayer(IP):
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            if pkt.haslayer(TCP):
                proto  = "TCP"
                flags  = pkt[TCP].flags
                flag_s = ""
                if flags & 0x02: flag_s += "S"
                if flags & 0x10: flag_s += "A"
                if flags & 0x01: flag_s += "F"
                if flags & 0x04: flag_s += "R"
                info = (f":{pkt[TCP].sport} → :{pkt[TCP].dport}"
                        + (f" [{flag_s}]" if flag_s else ""))
            elif pkt.haslayer(UDP):
                proto = "UDP"
                info  = (f":{pkt[UDP].sport} → :{pkt[UDP].dport}"
                         f"  {size}B")
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                itype = pkt[ICMP].type
                info  = f"type={itype}  {size}B"
            else:
                proto = "IP"
                info  = f"{size}B"

        alert_str = " | ".join(alerts) if alerts else ""

        # Track device
        self.device_tracker.touch(
            src_ip, dst_ip, src_mac, size, ts)

        # Enrich DNS / Geo (non-blocking)
        if src_ip and src_ip != "N/A":
            if self._dns_enabled.get():
                hn = self.dns_cache.get(src_ip)
                if hn:
                    self.device_tracker.update_dns(src_ip, hn)
            if (self._geo_enabled.get()
                    and not _is_private(src_ip)):
                geo = self.geo_cache.get(src_ip)
                if geo:
                    self.device_tracker.update_geo(src_ip, geo)

        # Stats
        with self._stats_lock:
            self._pkt_total += 1
            self._pkt_window.append(time.monotonic())
            self._proto_count[proto] += 1
            if alerts:
                self._pkt_alerts += 1

        record = {
            "time":    ts,
            "src_ip":  src_ip,
            "dst_ip":  dst_ip,
            "src_mac": src_mac,
            "proto":   proto,
            "size":    size,
            "payload": info,
            "alert":   alert_str,
        }
        self.after(0, self._update_tree, record)
        if alerts:
            for a in alerts:
                self.after(0, self._add_alert_log, ts, a, record)
            self.after(0, self._trigger_alert_visual)

    # ════════════════════════════════════════════════════════════
    #  TREE / TABLE MANAGEMENT
    # ════════════════════════════════════════════════════════════
    def _update_tree(self, data: dict):
        filt = self._proto_filter.get()
        with self._packets_lock:
            if len(self.table_packets) >= MAX_TABLE_ROWS:
                self.table_packets.pop(0)
            self.table_packets.append(data)
        if filt != "ALL" and data["proto"] != filt:
            return
        vals = (
            data["time"], data["src_ip"], data["dst_ip"],
            data["src_mac"], data["proto"], data["size"],
            data["payload"],
            data["alert"][:60] if data["alert"] else "")
        tag = (("alert",) if data["alert"]
               else (data["proto"].lower(),)
               if data["proto"] in ("ARP","TCP","UDP","ICMP")
               else ())
        with self._packets_lock:
            idx = len(self.table_packets) - 1
        self.tree.insert("", "end",
                         text=str(idx), values=vals, tags=tag)
        children = self.tree.get_children()
        if len(children) > MAX_TREE_ROWS:
            self.tree.delete(children[0])
        if self._autoscroll.get():
            self.tree.yview_moveto(1)

    def _apply_filter(self):
        filt = self._proto_filter.get()
        for i in self.tree.get_children():
            self.tree.delete(i)
        with self._packets_lock:
            snapshot = list(enumerate(self.table_packets))
        for real_idx, data in snapshot:
            if filt != "ALL" and data["proto"] != filt:
                continue
            vals = (
                data["time"], data["src_ip"], data["dst_ip"],
                data["src_mac"], data["proto"], data["size"],
                data["payload"],
                data["alert"][:60] if data["alert"] else "")
            tag = (("alert",) if data["alert"]
                   else (data["proto"].lower(),)
                   if data["proto"] in ("ARP","TCP","UDP","ICMP")
                   else ())
            self.tree.insert("", "end",
                             text=str(real_idx), values=vals, tags=tag)

    def _sort_tree(self, col: str):
        """Sort packet table by column header click."""
        pass   # placeholder — stateless sort for live data is complex

    def _sort_dev_tree(self, col: str):
        """Sort device table by column."""
        pass

    # ════════════════════════════════════════════════════════════
    #  ARP TABLE
    # ════════════════════════════════════════════════════════════
    def _update_dev_ui(self):
        self.dev_list.delete(0, tk.END)
        for ip, mac in sorted(self.ip_mac_map.items()):
            self.dev_list.insert(tk.END, f"  {ip:<17}  {mac}")

    def _update_arp_record(self, ip: str, mac: str,
                            ts: str, suspicious: bool):
        if ip in self._arp_records:
            r = self._arp_records[ip]
            r["last"]  = ts
            r["count"] += 1
            if suspicious:
                r["status"] = "SUSPICIOUS"
        else:
            self._arp_records[ip] = {
                "mac": mac, "first": ts, "last": ts,
                "count": 1,
                "status": "SUSPICIOUS" if suspicious else "Trusted",
            }
        for i in self.arp_tree.get_children():
            self.arp_tree.delete(i)
        for ip_, r in sorted(self._arp_records.items()):
            tag = ("suspicious" if r["status"] == "SUSPICIOUS"
                   else "trusted",)
            self.arp_tree.insert("", "end", values=(
                ip_, r["mac"], r["first"], r["last"],
                r["count"], r["status"]), tags=tag)

    def _clear_arp_table(self):
        self._arp_records.clear()
        self.arp_engine.reset()
        for i in self.arp_tree.get_children():
            self.arp_tree.delete(i)

    # ════════════════════════════════════════════════════════════
    #  ALL DEVICES TAB
    # ════════════════════════════════════════════════════════════
    def _tick_devices(self):
        self._refresh_device_tab()
        self.after(2000, self._tick_devices)

    def _refresh_device_tab(self):
        gw = self.gw_entry.get().strip()
        devices = self.device_tracker.snapshot()
        for i in self.dev_tree.get_children():
            self.dev_tree.delete(i)
        for d in devices[:MAX_DEVICE_ROWS]:
            ip = d["ip"]
            # Refresh DNS
            dns = d.get("dns", "")
            if not dns and self._dns_enabled.get():
                dns = self.dns_cache.get(ip)
                if dns:
                    self.device_tracker.update_dns(ip, dns)
            # Refresh Geo
            geo = d.get("geo", {})
            if not geo and self._geo_enabled.get():
                geo = self.geo_cache.get(ip)
                if geo:
                    self.device_tracker.update_geo(ip, geo)
            # Format geo string
            if geo:
                city    = geo.get("city", "")
                country = geo.get("country", "")
                isp     = geo.get("isp", "")[:28]
                parts   = ", ".join(filter(None, [city, country]))
                geo_str = f"{parts}  [{isp}]" if (parts and isp
                    and isp not in ("Private Network","")) else (
                    parts or isp or "…")
            else:
                geo_str = "…"
            # Tag
            if ip == gw:
                tag = ("gateway",)
            elif _is_private(ip):
                tag = ("local",)
            else:
                tag = ("external",)
            self.dev_tree.insert("", "end", values=(
                ip,
                (dns or "…")[:38],
                (geo_str or "…")[:42],
                d.get("mac", "")[:17],
                _fmt_bytes(d.get("bytes_out", 0)),
                _fmt_bytes(d.get("bytes_in",  0)),
                d.get("pkts", 0),
                d.get("last", ""),
            ), tags=tag)

    # ════════════════════════════════════════════════════════════
    #  ALERTS
    # ════════════════════════════════════════════════════════════
    def _add_alert_log(self, ts: str, alert_text: str, rec: dict):
        t = self._alert_log
        t.config(state="normal")
        t.insert("end", f"[{ts}]  {alert_text}\n")
        t.insert("end",
                 f"  Src: {rec['src_ip']}  "
                 f"MAC: {rec['src_mac']}\n")
        t.insert("end", f"  {'─'*58}\n")
        t.see("end")
        t.config(state="disabled")
        self._alert_count_lbl.config(
            text=f"  {self._pkt_alerts} alerts")

    def _clear_alerts(self):
        self._alert_log.config(state="normal")
        self._alert_log.delete(1.0, tk.END)
        self._alert_log.config(state="disabled")

    def _trigger_alert_visual(self):
        if self._alert_active:
            return
        self._alert_active = True
        if self._sound_enabled.get():
            self.bell()
        self._alert_banner.pack(fill="x")
        self._flash_count = 0
        self._flash()

    def _flash(self):
        if self._flash_count >= 12:
            self._alert_active = False
            self._alert_banner.pack_forget()
            return
        vis = self._flash_count % 2 == 0
        self._alert_banner.config(
            bg="#2d0f0f" if vis else BG5,
            fg="#ff6b6b" if vis else "#2d0f0f")
        self._flash_count += 1
        self.after(350, self._flash)

    # ════════════════════════════════════════════════════════════
    #  STATS TICK
    # ════════════════════════════════════════════════════════════
    def _tick_stats(self):
        with self._stats_lock:
            total  = self._pkt_total
            alerts = self._pkt_alerts
            now    = time.monotonic()
            # count packets in last second
            cutoff = now - 1.0
            rate   = sum(1 for t in self._pkt_window if t >= cutoff)
            arp_c  = self._proto_count["ARP"]
            tcp_c  = self._proto_count["TCP"]
            udp_c  = self._proto_count["UDP"]
            icmp_c = self._proto_count["ICMP"]

        elapsed = now - self._capture_start if self._capture_start else 0
        h, rem  = divmod(int(elapsed), 3600)
        m, s    = divmod(rem, 60)
        uptime  = f"{h:02d}:{m:02d}:{s:02d}" if self._capture_start else "--"

        self._stat_lbl["total"].config(text=str(total))
        self._stat_lbl["rate"].config(text=str(rate))
        self._stat_lbl["alerts"].config(text=str(alerts))
        self._stat_lbl["devices"].config(
            text=str(self.device_tracker.count()))
        self._stat_lbl["arp"].config(text=str(arp_c))
        self._stat_lbl["tcp"].config(text=str(tcp_c))
        self._stat_lbl["udp"].config(text=str(udp_c))
        self._stat_lbl["icmp"].config(text=str(icmp_c))
        self._stat_lbl["uptime"].config(text=uptime)
        self.after(1000, self._tick_stats)

    # ════════════════════════════════════════════════════════════
    #  ROW SELECT → DETAIL PANEL
    # ════════════════════════════════════════════════════════════
    def _on_row_select(self, _event=None):
        sel = self.tree.selection()
        if not sel:
            return
        try:
            real_idx = int(self.tree.item(sel[0], "text"))
            with self._packets_lock:
                pkt = self.table_packets[real_idx]
        except (ValueError, IndexError):
            return

        src_ip = pkt["src_ip"]
        dns = self.dns_cache.get(src_ip) if src_ip != "N/A" else ""
        geo = self.geo_cache.get(src_ip) if src_ip != "N/A" else {}
        geo_str = ""
        if geo and geo.get("country", "") not in ("", "?"):
            city    = geo.get("city", "")
            country = geo.get("country", "")
            isp     = geo.get("isp", "")
            parts   = ", ".join(filter(None, [city, country]))
            geo_str = f"{parts}  [{isp}]" if isp else parts

        lines = [
            "╔══ PACKET ANALYSIS ══════════════════════════════════════",
            f"║  Time       : {pkt['time']}",
            f"║  Protocol   : {pkt['proto']}",
            f"║  Source IP  : {src_ip}",
        ]
        if dns and dns != src_ip:
            lines.append(f"║  Hostname   : {dns}")
        if geo_str:
            lines.append(f"║  GeoIP      : {geo_str}")
        lines += [
            f"║  Source MAC : {pkt['src_mac']}",
            f"║  Dest IP    : {pkt['dst_ip']}",
            f"║  Size       : {pkt['size']} bytes",
            f"║  Info       : {pkt['payload']}",
        ]
        if pkt["alert"]:
            lines.append(f"║")
            lines.append(f"║  ⚠ ALERT    : {pkt['alert']}")
        lines.append("╚══════════════════════════════════════════════════════════")

        self.details.delete(1.0, tk.END)
        self.details.insert(tk.END, "\n".join(lines))

    # ════════════════════════════════════════════════════════════
    #  CLEAR ALL
    # ════════════════════════════════════════════════════════════
    def _clear_all(self):
        if self.capturing:
            messagebox.showwarning(
                "Capture running",
                "Stop capture before clearing.", parent=self)
            return
        with self._packets_lock:
            self.table_packets.clear()
            self.ip_mac_map.clear()
        self._arp_records.clear()
        self.arp_engine.reset()
        self.device_tracker.reset()
        with self._stats_lock:
            self._pkt_total  = 0
            self._pkt_alerts = 0
            self._pkt_window.clear()
            self._proto_count.clear()
        for tree in (self.tree, self.arp_tree, self.dev_tree):
            for i in tree.get_children():
                tree.delete(i)
        self.dev_list.delete(0, tk.END)
        self.details.delete(1.0, tk.END)
        self._clear_alerts()
        self._capture_start = 0.0
        self.status_bar.config(
            text="  Cleared — ready for new capture", fg="#888")


    # ════════════════════════════════════════════════════════════
    #  OFFLINE PCAP LOAD (v1.1) — no live capture required
    # ════════════════════════════════════════════════════════════
    def load_pcap(self):
        """Replay a PCAP through the same analysis pipeline (sandbox-safe)."""
        if self.capturing:
            messagebox.showwarning(
                "Busy", "Stop live capture before loading a PCAP.", parent=self)
            return
        path = filedialog.askopenfilename(
            parent=self,
            title="Open PCAP for analysis",
            filetypes=[
                ("PCAP files", "*.pcap *.pcapng *.cap"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        # Path safety: reject null / non-files
        if "\x00" in path or not os.path.isfile(path):
            messagebox.showerror("Invalid path", "File not found or unsafe.", parent=self)
            return
        self.status_bar.config(
            text=f"  Loading PCAP: {os.path.basename(path)} …", fg=GOLD)
        threading.Thread(
            target=self._load_pcap_worker, args=(path,),
            daemon=True, name="pcap-loader").start()

    def _load_pcap_worker(self, path: str):
        try:
            from scapy.all import rdpcap
            pkts = rdpcap(path)
        except Exception as exc:
            self.after(0, self.status_bar.config,
                       {"text": f"  PCAP load error: {exc}", "fg": ACCENT})
            return
        count = 0
        for pkt in pkts:
            try:
                self._process_packet(pkt)
                count += 1
            except Exception:
                continue
        self.after(0, self.status_bar.config, {
            "text": f"  Loaded {count} packet(s) from {os.path.basename(path)}",
            "fg": PRIMARY,
        })

    # ════════════════════════════════════════════════════════════
    #  EXPORT (user-driven dialog)
    # ════════════════════════════════════════════════════════════
    def _open_export(self):
        with self._packets_lock:
            snap = list(self.table_packets)
        if not snap and self.device_tracker.count() == 0:
            messagebox.showwarning(
                "Nothing to export",
                "No data captured yet.", parent=self)
            return
        ExportDialog(self, snap, self._arp_records,
                     self.device_tracker,
                     self._pkt_total, self._pkt_alerts)

    # ════════════════════════════════════════════════════════════
    #  HELP WINDOW
    # ════════════════════════════════════════════════════════════
    def show_help(self):
        HelpWindow(self)

    # ════════════════════════════════════════════════════════════
    #  EXIT
    # ════════════════════════════════════════════════════════════
    def safe_exit(self):
        self.capturing = False
        self.after(100, self.destroy)


# ════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser(prog="ONetWatch",
                                 description=f"{APP_NAME} {VERSION}")
    ap.add_argument("--version", action="version",
                    version=f"{APP_NAME} {VERSION}")
    ap.add_argument("--pcap", metavar="FILE",
                    help="Load a PCAP offline (no live capture; root not required)")
    ap.add_argument("--no-geo", action="store_true",
                    help="Disable GeoIP external lookups")
    args, _unknown = ap.parse_known_args()

    need_root = not args.pcap
    if need_root and platform.system() != "Windows" and os.geteuid() != 0:
        print(
            f"\n  [!] {APP_NAME} {VERSION} requires root to capture packets.\n"
            f"      Run:  sudo ONetWatch\n"
            f"      Or:   ONetWatch --pcap /path/to/file.pcap\n")
        sys.exit(1)

    app = ONetWatchApp()
    if args.no_geo:
        app._geo_enabled.set(False)
    if args.pcap:
        app.after(400, lambda: app._load_pcap_worker(args.pcap)
                  if os.path.isfile(args.pcap)
                  else app.status_bar.config(
                      text=f"  PCAP not found: {args.pcap}", fg=ACCENT))
    app.mainloop()
