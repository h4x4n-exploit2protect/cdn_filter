"EXPLOIT2PROTECT" / CDN Filter

<p align="center">
  <img src="https://img.shields.io/badge/EXPLOIT2PROTECT-Security%20Tools-00D4AA?style=for-the-badge" alt="Exploit2Protect">
  <img src="https://img.shields.io/badge/Python-3.9%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/badge/IPv4%20%7C%20IPv6-Supported-6366F1?style=for-the-badge" alt="IPv4 and IPv6">
</p><p align="center">
  <strong>CDN & Historical DNS IP Analyzer</strong>
  <br>
  Identify known CDN and cloud-hosting ranges from historical DNS IP data.
  <br><br>
  <em>Turning Attacks into Defense.</em>
</p><p align="center">
  <a href="https://github.com/h4x4n-exploit2protect/cdn_filter">Repository</a>
  •
  <a href="#installation">Installation</a>
  •
  <a href="#usage">Usage</a>
  •
  <a href="#output-files">Output Files</a>
</p>---

Overview

Exploit2Protect CDN Filter is a lightweight Python utility for categorizing IP addresses collected from historical DNS records and authorized asset inventories.

It compares IP addresses against publicly available provider ranges and optionally uses reverse DNS (PTR) information to identify potential CDN and cloud-hosting indicators.

«Note: This tool provides preliminary classification, not proof of origin infrastructure or CDN/WAF bypass.»

Features

Feature| Description
IP Extraction| Extracts unique IPv4 and IPv6 addresses
Cloudflare| Matches published IPv4 and IPv6 ranges
Fastly| Checks published Fastly ranges
AWS| Classifies CloudFront, Global Accelerator, and other AWS ranges
Google Cloud| Checks published Google Cloud ranges
Reverse DNS| Identifies CDN and cloud-hosting hostname hints
Reports| Generates categorized text files and a TSV report
Lightweight| Uses Python's standard library

Installation

Requirements: Python 3.9+ and internet access for provider feeds.

git clone https://github.com/h4x4n-exploit2protect/cdn_filter.git
cd cdn_filter
chmod +x cdn_filter.py

Usage

Quick Start

Analyze a file containing historical IP addresses:

python3 cdn_filter.py -iL historical-ips.txt

Custom Output Prefix

python3 cdn_filter.py -iL historical-ips.txt -o results/analysis

Skip Reverse DNS Lookups

python3 cdn_filter.py -iL historical-ips.txt -o results/analysis --no-ptr

Example: Historical DNS Candidates

python3 cdn_filter.py -iL orgin1.txt-candidates.txt -o results/origin-analysis

Replace the example filename with your own input file.

Output Files

The tool generates separate files for each classification.

Output| Purpose
"*-all.tsv"| Complete classification report
"*-known-cdn.txt"| IPs matching known CDN or edge ranges
"*-cdn-hints.txt"| IPs with CDN-related PTR hints
"*-cloud-hosting.txt"| IPs matching cloud-hosting ranges or PTR hints
"*-unclassified.txt"| IPs not matched by the available checks
"*-invalid.txt"| Input lines without a recognized IP address

Classification Workflow

Historical DNS / IP List
          |
          v
    Extract IP Addresses
          |
          v
  Published Provider Ranges
          |
          v
     Reverse DNS Hints
          |
          v
    Categorized Results
          |
          v
   TSV + Text Reports

Understanding the Results

- Known CDN: IP matches a published CDN or edge-related range.
- CDN Hints: PTR hostname contains a recognized CDN-related keyword.
- Cloud Hosting: IP matches a cloud-hosting range or PTR hint.
- Unclassified: No configured provider range or PTR hint matched.
- Invalid: The input line contained no recognized IP address.

Important Limitations

An unclassified IP is not necessarily an origin IP. It could belong to an unrecognized CDN, WAF, proxy, load balancer, hosting provider, or other infrastructure.

Other limitations include:

- Provider feeds can be unavailable or incomplete.
- Reverse DNS records may be missing, generic, or outdated.
- Cloud ranges may include both origin and intermediary infrastructure.
- A range match does not prove that a specific hostname uses that provider.
- Independent verification is required before drawing security conclusions.

Responsible Use

Use this tool only for assets you own or are explicitly authorized to assess.

This project does not attempt to bypass CDNs, WAFs, firewalls, or access controls. Follow the applicable scope, rules of engagement, and responsible disclosure requirements.

Project

<p align="center">
  <strong>EXPLOIT2PROTECT</strong>
  <br>
  <em>Turning Attacks into Defense</em>
  <br><br>
  <a href="https://github.com/h4x4n-exploit2protect/cdn_filter">View Source Code on GitHub</a>
</p>License

No license has been specified. Add a "LICENSE" file to define the terms for using, modifying, and redistributing this project.
