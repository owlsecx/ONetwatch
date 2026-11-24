# 🦉 ONetWatch

<p align="center">
  <img src="https://img.shields.io/badge/Platform-Linux-0a0c10?style=flat-square"/>
  <img src="https://img.shields.io/badge/Category-ONetwork-blue?style=flat-square"/>
  <img src="https://img.shields.io/badge/License-Proprietary-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/Part%20of-OwlSec%20Toolkit-7b5ea7?style=flat-square"/>
  <img src="https://img.shields.io/badge/Version-1.0.0-cyan?style=flat-square"/>
</p>

> **ONetWatch** — v1.1

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

This tool is part of the **OwlSec** suite — a collection of 275+ security and privacy tools.

🔗 [owlsec.org](https://owlsec.org)

---

## ©️ License

Proprietary — © 2026 Owlsec LLC. All rights reserved.

*Tools are distributed as pre-built executables. Source code is proprietary.*

---

## 🔍 Verification & Transparency

This tool is closed-source. These files let you see exactly what is inside it,
without the source:

- [`SBOM.cdx.json`](SBOM.cdx.json) — CycloneDX inventory: SHA-256 of this
  binary, bundled CPython version, and every bundled library with its exact
  version and license. Feed it to Grype, Trivy or Dependency-Track to audit
  our dependencies for CVEs yourself.
- [`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md) — the full license text
  of every third-party component, extracted from this binary.

**No telemetry, no analytics, no licence check-in.** This tool does not phone
home. Verify that claim yourself:

```bash
sudo strace -f -e trace=network ./ONetWatch --help   # watch every network call
firejail --net=none ./ONetWatch --help               # deny the network entirely
```

Release signing, GPL compliance and vulnerability reporting:
[**TRUST.md**](https://github.com/owlsecx/owl-os/blob/main/TRUST.md)
