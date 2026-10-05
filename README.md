# EXPLOIT2PROTECT / CDN Filter

<p align="center">
  <b>CDN & Historical DNS IP Analyzer</b><br>
  <i>Identify known CDN and cloud-hosting ranges from historical DNS IP data.</i><br>
  <sub>Turning Attacks into Defense</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/python-3.9+-blue.svg" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/dependencies-standard--lib-green.svg" alt="Zero Dependencies">
  <img src="https://img.shields.io/badge/license-Unlicensed-red.svg" alt="License">
</p>

---

## 📌 Overview

**Exploit2Protect CDN Filter** is a lightweight Python utility designed to categorize IP addresses gathered from historical DNS records, passive DNS datasets, and authorized asset inventories.

It compares target IPv4 and IPv6 addresses against published CIDR blocks from major providers and optionally performs reverse DNS (PTR) lookups to flag CDN and cloud-hosting infrastructure signatures.

> [!NOTE]
> This tool provides **preliminary classification** for security analysis and scope cleanup. It does **not** serve as absolute proof of origin infrastructure or CDN/WAF bypass.

---

## ✨ Features

| Feature | Description |
| :--- | :--- |
| **IP Extraction** | Automatically parses and deduplicates valid IPv4 and IPv6 addresses from unstructured text files. |
| **Cloudflare** | Matches published IPv4 and IPv6 range feeds. |
| **Fastly** | Checks against official Fastly IP ranges. |
| **AWS** | Classifies CloudFront, Global Accelerator, and broad AWS cloud ranges. |
| **Google Cloud** | Validates against published Google Cloud and cloud-edge ranges. |
| **Reverse DNS** | Identifies CDN/cloud hostname indicators via PTR lookups. |
| **Structured Output** | Generates filtered clean text lists alongside a detailed TSV report. |
| **Zero Dependencies** | Built using pure **Python Standard Library** modules (no `pip install` required). |

---

## ⚡ Installation

### Prerequisites
* **Python 3.9+**
* Active internet connection (to fetch live provider IP range feeds)

```bash
# Clone the repository
git clone https://github.com/h4x4n-exploit2protect/cdn_filter.git

# Navigate to directory
cd cdn_filter

# Make script executable
chmod +x cdn_filter.py
```

---

## 🚀 Usage

### Quick Start
Analyze a list of historical IP addresses using default settings:
```bash
python3 cdn_filter.py -iL historical-ips.txt
```

### Custom Output Directory & Prefix
```bash
python3 cdn_filter.py -iL historical-ips.txt -o results/analysis
```

### Fast Mode (Skip PTR Lookups)
To speed up execution on large IP lists, disable reverse DNS resolution:
```bash
python3 cdn_filter.py -iL historical-ips.txt -o results/analysis --no-ptr
```

---

## 🔄 Classification Workflow

```text
       [ Historical DNS / IP List ]
                   │
                   ▼
         [ Extract & Dedupe IPs ]
                   │
                   ▼
     [ Check Provider Range Feeds ]
                   │
                   ▼
      [ Perform Reverse DNS (PTR) ]  <── (Optional)
                   │
                   ▼
       [ Categorized Output Files ]
      (TSV Report + Filtered Lists)
```

---

## 📁 Output Files

The tool automatically creates categorized output files based on your `-o` prefix:

| File Pattern | Description / Usage |
| :--- | :--- |
| `*-all.tsv` | Master TSV summary report detailing IP, classification, provider, and PTR metadata. |
| `*-known-cdn.txt` | IPs strictly matching known CDN or edge proxy network ranges. |
| `*-cdn-hints.txt` | IPs with CDN-related domain patterns detected in PTR hostnames. |
| `*-cloud-hosting.txt` | IPs belonging to general cloud-hosting providers (e.g., AWS EC2, GCP). |
| `*-unclassified.txt` | **Potential origin targets** (IPs not matching any known CDN/cloud signature). |
| `*-invalid.txt` | Malformed lines or unparseable input entries. |

---

## 🧠 Understanding the Classifications

* **Known CDN:** The IP directly falls within an officially published CDN range (e.g., Cloudflare, Fastly).
* **CDN Hints:** Reverse DNS resolution revealed hostname indicators associated with edge services.
* **Cloud Hosting:** Matches general cloud infrastructure CIDR blocks where origin servers or custom proxies might reside.
* **Unclassified:** The IP did not trigger any configured range or PTR rule.
* **Invalid:** Input line contained invalid IP syntax.

---

## ⚠️ Limitations

An **Unclassified** IP address is not guaranteed to be a direct origin server. Keep in mind:
1. Target infrastructure may use lesser-known CDNs, WAFs, or regional hosting providers not present in the feeds.
2. Reverse DNS records can be unconfigured, generic, or stale.
3. Cloud ranges often host both edge proxies and origin web applications.
4. Always manually verify findings prior to reaching security conclusions.

---

## 🛡️ Responsible Use & Disclaimer

This tool is designed strictly for **authorized security testing**, asset management, and defensive research.

* Only execute this utility against target scopes you own or have explicit, written permission to test.
* This tool does **not** perform attacks or actively attempt to bypass security controls.
* Always adhere to applicable program rules of engagement and responsible disclosure guidelines.

---

## 📄 License

This project currently has no specified license. To define redistribution, modification, and usage rights for contributors and users, consider adding a standard `LICENSE` file (such as MIT or Apache 2.0).

---

<p align="center">
  <b>EXPLOIT2PROTECT</b><br>
  <i>Turning Attacks into Defense</i>
</p>
