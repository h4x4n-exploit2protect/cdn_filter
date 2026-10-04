
# Exploit2Protect CDN & Historical DNS IP Analyzer

**Turning Attacks into Defense**

A Python tool for categorizing IP addresses collected from historical DNS records and authorized asset inventories.

## Features

- Detects IP addresses in text, CSV, and TSV files
- Checks published Cloudflare IPv4 and IPv6 ranges
- Checks Fastly public IP ranges
- Checks AWS CloudFront and Global Accelerator ranges
- Identifies AWS and Google Cloud hosting ranges
- Optionally checks reverse DNS (PTR) hints
- Generates separate output files for each category
- Uses Python's standard library only

## Requirements

- Python 3.9 or later
- Internet access to retrieve provider IP range feeds
- Optional DNS access for reverse-DNS lookups

No third-party Python packages are required.

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/exploit2protect-cdn-analyzer.git
cd exploit2protect-cdn-analyzer
chmod +x cdn_filter.py
```

## Usage

Analyze a historical IP list:

```bash
python3 cdn_filter.py -iL historical-ips.txt
```

Specify a custom output prefix:

```bash
python3 cdn_filter.py -iL historical-ips.txt -o results/analysis
```

Skip reverse-DNS lookups:

```bash
python3 cdn_filter.py -iL historical-ips.txt -o results/analysis --no-ptr
```

## Output Files

| File | Description |
|---|---|
| `*-all.tsv` | Combined results with classification details |
| `*-known-cdn.txt` | IPs matching known CDN or edge ranges |
| `*-cdn-hints.txt` | IPs with CDN-related PTR hints |
| `*-cloud-hosting.txt` | IPs matching cloud-hosting ranges or PTR hints |
| `*-unclassified.txt` | IPs not matched by the available checks |
| `*-invalid.txt` | Input lines without a recognized IP address |

## How Classification Works

1. Extracts unique IPv4 and IPv6 addresses from the input.
2. Downloads publicly available provider IP range feeds.
3. Compares each address against the loaded ranges.
4. Optionally checks reverse DNS when no range matches.
5. Saves the categorized results to files.

## Limitations

- An unclassified IP is **not necessarily an origin server**.
- Cloud-hosting IPs can serve legitimate origin servers, proxies, load balancers, or other services.
- CDN providers may not publish every relevant range.
- PTR records can be missing, generic, or outdated.
- A CDN range match does not prove that a particular hostname uses that provider.
- Provider feeds can be unavailable or change over time.
- This tool does not attempt to bypass a CDN, WAF, firewall, or access control.

Use the results as preliminary intelligence and verify findings independently.

## Responsible Use

Use this tool only for assets you own or are authorized to assess. Follow the applicable scope, rules of engagement, and disclosure policies.

## Author

**Exploit2Protect**  
*Turning Attacks into Defense*
