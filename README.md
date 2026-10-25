# 🦉 ONetWatch

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-ONetwork-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-cyan?style=flat-square"/>
</p>

> **ONetWatch** — v1.1 ║

---

> ⚠️ **AUTHORISED USE ONLY** — Use only on systems you own or have explicit written permission to test. Unauthorised use is illegal.

---

## 📌 Overview

ONetWatch is a network monitoring and packet-sentinel tool for ARP/TCP/UDP/ICMP/IP capture with ARP spoofing detection (IP-MAC mismatch, gratuitous ARP, flood, gateway impersonation). It offers DNS PTR caching, optional GeoIP, device tracking, alerts, and CSV/JSON/TXT export. Live capture typically needs root; `--pcap` enables offline analysis without root.

---

## ✨ Features

- Real-time packet capture for ARP / TCP / UDP / ICMP / IP
- ARP spoofing detection: IP-MAC mismatch, gratuitous ARP, ARP flood, gateway impersonation
- Background DNS PTR resolver with TTL cache; optional GeoIP (disable with `--no-geo`)
- All-device tracker with per-device bandwidth and protocol filter bar
- Alert flash and audio bell on MITM-style events
- Export results to CSV / JSON / TXT; offline `--pcap` mode without live capture

---

## ⚙️ Requirements

- **Linux**
- **No Python installation needed** — runs as a standalone executable

---

## 🚀 Usage

```bash
./ONetwatch --pcap capture.pcap --no-geo
./ONetwatch --pcap sample.pcap
./ONetwatch --help
```

---

## 📦 Part of OwlSec Toolkit

This tool is part of the **OwlSec** suite — a collection of 300+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

MIT License — © Khaled S. Haddad

*Tools are distributed as pre-built executables. Source code is proprietary.*
