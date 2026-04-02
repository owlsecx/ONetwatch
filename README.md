# 🕵️ ONetWatch

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux%20%2F%20Windows-informational?style=flat-square&logo=linux&logoColor=white&color=0a0c10"/>
  <img src="https://img.shields.io/badge/Category-ONetwork%20%2F%20Monitoring%20%26%20MITM-cyan?style=flat-square"/>
  <img src="https://img.shields.io/badge/Dependencies-None%20(Standalone)-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Proprietary-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-v1.0-cyan?style=flat-square"/>
</p>

> **ONetWatch** is a real-time network monitoring and MITM detection tool. It captures packets, detects ARP spoofing, IP-MAC mismatches, ARP floods, gateway impersonation, and tracks every device on the network with DNS resolution and GeoIP lookup.

---

## 📌 Overview

ONetWatch provides a clean GUI dashboard with live packet analysis, ARP table monitoring, all-devices tracking (not just ARP), protocol statistics, visual alerts, and instant export. It detects classic MITM attacks and suspicious network behavior in real time while remaining lightweight and easy to use.

---

## 🖥️ Features

| Feature | Description |
|---------|-------------|
| **Live Packet Capture** | Full packet sniffing with protocol breakdown (ARP, TCP, UDP, ICMP…) |
| **ARP Attack Detection** | IP-MAC mismatch, Gratuitous ARP, ARP flood, Gateway impersonation |
| **All Devices Table** | Tracks every IP seen (ARP + TCP + UDP) with bytes sent/received |
| **DNS Resolution** | Background PTR lookup with caching |
| **GeoIP Lookup** | Country, city, ISP via ip-api.com (cached) |
| **Smart Alerts** | Visual flash banner + audio bell on MITM events |
| **Statistics Dashboard** | Packets/sec, total packets, alerts, ARP rate, all IPs count |
| **Protocol Filter** | Quick filter: ALL / ARP / TCP / UDP / ICMP / Other |
| **Export** | CSV and JSON reports of all captured packets and devices |

---

## 📊 Interface Sections

- **Dashboard**: Real-time stats (packets, rate, alerts, all IPs)
- **Packets Tab**: Live table with timestamp, IPs, MAC, protocol, size, payload, alerts
- **ARP Table Tab**: Trusted baseline with suspicious highlighting
- **All Devices Tab**: Complete view of every IP on the network (NEW in v1.0)
- **Alerts Tab**: Full log of security events
- **Details Panel**: Click any packet → enriched info (DNS + GeoIP)

---

## ⚙️ Requirements

- **Linux or Windows**
- **No Python installation needed** — runs as a standalone executable
- **Requires root/admin privileges** for packet capture

---

## 🚀 Usage

```bash
sudo ./ONetWatch

📁 Output

CSV Export: Full packet log with timestamps and alerts
JSON Export: Complete structured report (packets + ARP table + all devices)


📦 Part of OwlSec Toolkit
This tool is part of the OwlSec suite — a collection of 300+ security and privacy tools.
🔗 owlsec.org

©️ License
Proprietary — © Khaled S. Haddad
Tools are distributed as pre-built executables. Source code is proprietary.

AUTHORISED NETWORK MONITORING USE ONLY
