Exploit2Protect CDN Filter

CDN & Historical DNS IP Analyzer

Turning Attacks into Defense

A lightweight Python tool that analyzes historical DNS IP addresses and categorizes them using published CDN/cloud IP ranges and reverse DNS (PTR) hints.

Repository: "h4x4n-exploit2protect/cdn_filter" (https://github.com/h4x4n-exploit2protect/cdn_filter)

Features

- IPv4 and IPv6 extraction from text-based input files
- Cloudflare published IP range detection
- Fastly public IP range detection
- AWS CloudFront and Global Accelerator classification
- AWS cloud-hosting IP range classification
- Google Cloud IP range classification
- Optional reverse DNS (PTR) analysis
- CDN-related and cloud-hosting hostname hints
- Categorized output files
- Combined TSV report
- Python standard library only; no third-party dependencies

Requirements

- Python 3.9+
- Internet connectivity to download provider IP range feeds
- DNS connectivity for reverse DNS lookups

Installation

git clone https://github.com/h4x4n-exploit2protect/cdn_filter.git
cd cdn_filter
chmod +x cdn_filter.py

Usage

Basic scan

python3 cdn_filter.py -iL historical-ips.txt

Specify an output prefix

python3 cdn_filter.py -iL historical-ips.txt -o results/analysis

Skip reverse DNS lookups

python3 cdn_filter.py -iL historical-ips.txt -o results/analysis --no-ptr

Example with historical DNS IPs

python3 cdn_filter.py -iL orgin1.txt-candidates.txt -o results/origin-analysis

Replace the input filename with your own authorized asset inventory.

Output Files

File| Description
"*-all.tsv"| Complete classification report
"*-known-cdn.txt"| IPs matching known CDN or edge-related ranges
"*-cdn-hints.txt"| IPs with CDN-related PTR hints
"*-cloud-hosting.txt"| IPs matching cloud-hosting ranges or PTR hints
"*-unclassified.txt"| IPs not matched by available checks
"*-invalid.txt"| Input lines without a recognized IP address

Classification Methodology

1. Reads the input file and extracts unique IPv4 and IPv6 addresses.
2. Downloads publicly available provider IP range feeds.
3. Compares addresses against known provider ranges.
4. Optionally performs reverse DNS lookups.
5. Categorizes the addresses and generates reports.

Understanding the Results

Known CDN: The IP matches a published CDN or edge-related network range.

CDN Hints: The IP did not match a loaded provider range but its PTR hostname contains a recognized CDN-related keyword.

Cloud Hosting: The IP matches a recognized cloud-hosting range or a cloud-related PTR hint.

Unclassified: The available checks did not identify a recognized provider range or PTR hint.

«Important: An unclassified IP is not necessarily an origin server. It may belong to an unrecognized CDN, WAF, proxy, load balancer, hosting provider, or other infrastructure. All findings require independent verification.»

Limitations

- Provider feeds may be unavailable or incomplete.
- Only configured providers and published ranges are checked.
- Reverse DNS records can be missing, generic, or outdated.
- Cloud-hosting IPs may serve origins, proxies, or intermediary services.
- A range match does not prove that a particular hostname uses that provider.
- The tool does not bypass CDNs, WAFs, firewalls, or access controls.
- Results are preliminary indicators, not proof of origin infrastructure.

Responsible Use

Use this tool only on assets you own or are explicitly authorized to assess. Follow the applicable scope, rules of engagement, and responsible disclosure policies.

Author

Exploit2Protect

Turning Attacks into Defense

GitHub: "h4x4n-exploit2protect/cdn_filter" (https://github.com/h4x4n-exploit2protect/cdn_filter)
