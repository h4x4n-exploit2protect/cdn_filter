
#!/usr/bin/env python3
"""
EXPLOIT2PROTECT
CDN & Historical DNS IP Analyzer

Turning Attacks into Defense

Purpose:
    Categorize IP addresses found in historical DNS or asset inventory
    files using published CDN/cloud IP ranges and optional reverse DNS.

Important:
    - This tool does NOT prove that an IP is an origin server.
    - An IP outside known CDN ranges may still belong to a CDN, proxy,
      WAF, load balancer, or other hosting provider.
    - Use only for authorized security assessments.

Dependencies:
    Python 3.9+
    Standard library only
"""

import argparse
import ipaddress
import json
import re
import socket
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


BANNER = r"""
============================================================
  EXPLOIT2PROTECT
  CDN & Historical DNS IP Analyzer
  Turning Attacks into Defense
============================================================
"""

USER_AGENT = "Exploit2Protect-CDN-Analyzer/1.0"
TIMEOUT = 12

FEEDS = {
    "Cloudflare": "https://www.cloudflare.com/ips-v4",
    "Cloudflare IPv6": "https://www.cloudflare.com/ips-v6",
    "Fastly": "https://api.fastly.com/public-ip-list",
    "AWS": "https://ip-ranges.amazonaws.com/ip-ranges.json",
    "Google Cloud": "https://www.gstatic.com/ipranges/cloud.json",
}

# These providers are recognized using PTR names when available.
CDN_PTR_HINTS = (
    "cloudflare",
    "cloudfront",
    "fastly",
    "akamaitechnologies",
    "akamai",
    "edgekey",
    "edgesuite",
    "azureedge",
    "azurefd",
    "trafficmanager",
    "cdn77",
    "stackpath",
    "bunnycdn",
    "imperva",
    "incapdns",
    "sucuri",
    "limelight",
    "llnw",
)

CLOUD_PTR_HINTS = (
    "amazonaws.com",
    "compute.amazonaws.com",
    "googleusercontent.com",
    "googlecloud",
    "azure.com",
    "cloudapp.azure.com",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "oraclecloud",
)

# Extract IPv4 and IPv6 strings from common text/CSV/TSV files.
IP_PATTERN = re.compile(
    r"(?<![0-9A-Fa-f:.])"
    r"(?:"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"|"
    r"[0-9A-Fa-f:]{2,}"
    r")"
    r"(?![0-9A-Fa-f:.])"
)


def fetch_url(url):
    """Fetch a public feed and return its content."""
    request = urllib.request.Request(
        url,
        headers={"User-Agent": USER_AGENT},
    )

    with urllib.request.urlopen(request, timeout=TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")


def add_network(networks, cidr, provider, category):
    """Parse a CIDR and add it to the network collection."""
    try:
        network = ipaddress.ip_network(cidr.strip(), strict=False)
        networks.append({
            "network": network,
            "provider": provider,
            "category": category,
        })
    except (ValueError, AttributeError):
        pass


def load_provider_ranges():
    """
    Load published provider IP ranges.

    Returns:
        list of dictionaries containing network, provider, and category.
    """
    networks = []
    feed_errors = []

    # Cloudflare IPv4 and IPv6
    for label in ("Cloudflare", "Cloudflare IPv6"):
        try:
            content = fetch_url(FEEDS[label])
            for line in content.splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    add_network(
                        networks,
                        line,
                        "Cloudflare",
                        "known-cdn",
                    )
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            feed_errors.append(f"{label}: {exc}")

    # Fastly public IP list
    try:
        data = json.loads(fetch_url(FEEDS["Fastly"]))
        for key in ("addresses", "ipv6_addresses"):
            for cidr in data.get(key, []):
                add_network(
                    networks,
                    cidr,
                    "Fastly",
                    "known-cdn",
                )
    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
        AttributeError,
    ) as exc:
        feed_errors.append(f"Fastly: {exc}")

    # AWS ranges. CloudFront and Global Accelerator are categorized
    # as edge/CDN-related; EC2 and other AWS services are cloud hosting.
    try:
        data = json.loads(fetch_url(FEEDS["AWS"]))

        for item in data.get("prefixes", []):
            service = item.get("service", "").upper()
            cidr = item.get("ip_prefix")

            if not cidr:
                continue

            if service in ("CLOUDFRONT", "GLOBALACCELERATOR"):
                category = "known-cdn"
                provider = f"AWS {service}"
            else:
                category = "cloud-hosting"
                provider = f"AWS {service or 'UNKNOWN'}"

            add_network(networks, cidr, provider, category)

        for item in data.get("ipv6_prefixes", []):
            service = item.get("service", "").upper()
            cidr = item.get("ipv6_prefix")

            if not cidr:
                continue

            if service in ("CLOUDFRONT", "GLOBALACCELERATOR"):
                category = "known-cdn"
                provider = f"AWS {service}"
            else:
                category = "cloud-hosting"
                provider = f"AWS {service or 'UNKNOWN'}"

            add_network(networks, cidr, provider, category)

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
        AttributeError,
    ) as exc:
        feed_errors.append(f"AWS: {exc}")

    # Google Cloud published ranges.
    try:
        data = json.loads(fetch_url(FEEDS["Google Cloud"]))

        for item in data.get("prefixes", []):
            cidr = item.get("ipv4Prefix") or item.get("ipv6Prefix")

            if cidr:
                add_network(
                    networks,
                    cidr,
                    "Google Cloud",
                    "cloud-hosting",
                )

    except (
        urllib.error.URLError,
        TimeoutError,
        OSError,
        json.JSONDecodeError,
        AttributeError,
    ) as exc:
        feed_errors.append(f"Google Cloud: {exc}")

    return networks, feed_errors


def extract_ips(line):
    """Extract valid IP addresses from a line of text."""
    found = []

    for candidate in IP_PATTERN.findall(line):
        try:
            ip = ipaddress.ip_address(candidate)
            found.append(str(ip))
        except ValueError:
            continue

    return found


def read_input_file(input_path):
    """Read the input file and collect unique IP addresses."""
    ips = set()
    invalid_lines = []

    with open(input_path, "r", encoding="utf-8", errors="replace") as file:
        for line_number, raw_line in enumerate(file, start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            extracted = extract_ips(line)

            if extracted:
                ips.update(extracted)
            else:
                invalid_lines.append(
                    f"{line_number}\t{line}"
                )

    return sorted(
        ips,
        key=lambda item: (
            ipaddress.ip_address(item).version,
            int(ipaddress.ip_address(item)),
        ),
    ), invalid_lines


def reverse_dns(ip):
    """Return the PTR hostname, or an empty string if unavailable."""
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname.rstrip(".").lower()
    except (socket.herror, socket.gaierror, OSError, TimeoutError):
        return ""


def classify_ip(ip, networks, do_ptr=True):
    """
    Classify an IP using published ranges and optional PTR hints.

    Range matches take precedence over PTR hints.
    """
    address = ipaddress.ip_address(ip)
    range_matches = []

    for entry in networks:
        network = entry["network"]

        if address.version != network.version:
            continue

        if address in network:
            range_matches.append(entry)

    if range_matches:
        # Prefer CDN classification if multiple provider ranges overlap.
        range_matches.sort(
            key=lambda item: (
                item["category"] != "known-cdn",
                item["network"].prefixlen * -1,
            )
        )
        match = range_matches[0]

        return {
            "ip": ip,
            "category": match["category"],
            "provider": match["provider"],
            "matched_range": str(match["network"]),
            "ptr": "",
            "note": "Matched published provider range",
        }

    ptr = reverse_dns(ip) if do_ptr else ""

    for hint in CDN_PTR_HINTS:
        if hint in ptr:
            return {
                "ip": ip,
                "category": "cdn-hints",
                "provider": "PTR hint",
                "matched_range": "",
                "ptr": ptr,
                "note": f"PTR contains CDN-related keyword: {hint}",
            }

    for hint in CLOUD_PTR_HINTS:
        if hint in ptr:
            return {
                "ip": ip,
                "category": "cloud-hosting",
                "provider": "PTR hint",
                "matched_range": "",
                "ptr": ptr,
                "note": f"PTR contains cloud-hosting keyword: {hint}",
            }

    return {
        "ip": ip,
        "category": "unclassified",
        "provider": "Unknown",
        "matched_range": "",
        "ptr": ptr,
        "note": (
            "No known range or PTR hint matched; "
            "this does not prove the IP is an origin"
        ),
    }


def write_outputs(prefix, results, invalid_lines):
    """Write categorized text files and a combined TSV report."""
    output_prefix = Path(prefix)
    output_prefix.parent.mkdir(parents=True, exist_ok=True)

    categories = {
        "known-cdn": [],
        "cdn-hints": [],
        "cloud-hosting": [],
        "unclassified": [],
    }

    for result in results:
        categories[result["category"]].append(result)

    all_file = Path(f"{prefix}-all.tsv")
    with all_file.open("w", encoding="utf-8") as file:
        file.write(
            "IP\tCategory\tProvider\tMatched_Range\tPTR\tNote\n"
        )
        for result in results:
            values = [
                result["ip"],
                result["category"],
                result["provider"],
                result["matched_range"],
                result["ptr"],
                result["note"],
            ]
            file.write("\t".join(values) + "\n")

    output_names = {
        "known-cdn": f"{prefix}-known-cdn.txt",
        "cdn-hints": f"{prefix}-cdn-hints.txt",
        "cloud-hosting": f"{prefix}-cloud-hosting.txt",
        "unclassified": f"{prefix}-unclassified.txt",
    }

    for category, filename in output_names.items():
        with open(filename, "w", encoding="utf-8") as file:
            for result in categories[category]:
                file.write(result["ip"] + "\n")

    invalid_file = Path(f"{prefix}-invalid.txt")
    with invalid_file.open("w", encoding="utf-8") as file:
        for line in invalid_lines:
            file.write(line + "\n")

    return categories, [str(all_file), *output_names.values(), str(invalid_file)]


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description=(
            "Classify historical DNS IP addresses using published "
            "CDN/cloud ranges and optional reverse-DNS hints."
        ),
        epilog=(
            "Example: python3 cdn_filter.py "
            "-iL historical-ips.txt -o results/analysis"
        ),
    )

    parser.add_argument(
        "-iL",
        "--input-list",
        required=True,
        dest="input_file",
        help="Input file containing IP addresses or DNS records",
    )
    parser.add_argument(
        "-o",
        "--output-prefix",
        default="exploit2protect-results",
        help="Output file prefix (default: exploit2protect-results)",
    )
    parser.add_argument(
        "--no-ptr",
        action="store_true",
        help="Skip reverse-DNS lookups",
    )

    args = parser.parse_args()

    input_path = Path(args.input_file)

    if not input_path.is_file():
        print(f"[!] Input file not found: {input_path}", file=sys.stderr)
        return 2

    print(f"[*] Input file: {input_path}")
    print("[*] Loading published provider ranges...")

    networks, feed_errors = load_provider_ranges()

    print(f"[*] Loaded {len(networks)} network entries.")

    if feed_errors:
        print("[!] Some provider feeds could not be loaded:")
        for error in feed_errors:
            print(f"    - {error}")
        print("[!] Results may be incomplete.")

    try:
        ips, invalid_lines = read_input_file(input_path)
    except OSError as exc:
        print(f"[!] Could not read input file: {exc}", file=sys.stderr)
        return 2

    print(f"[*] Unique valid IPs: {len(ips)}")
    print(f"[*] Invalid/unrecognized lines: {len(invalid_lines)}")

    results = []

    for index, ip in enumerate(ips, start=1):
        print(f"\r[*] Analyzing {index}/{len(ips)}: {ip}", end="", flush=True)

        try:
            result = classify_ip(
                ip,
                networks,
                do_ptr=not args.no_ptr,
            )
            results.append(result)
        except Exception as exc:
            print(f"\n[!] Could not classify {ip}: {exc}")

    if ips:
        print()

    try:
        categories, files = write_outputs(
            args.output_prefix,
            results,
            invalid_lines,
        )
    except OSError as exc:
        print(f"[!] Could not write output files: {exc}", file=sys.stderr)
        return 2

    print("\n[*] Analysis complete.")
    print(f"[*] Finished: {datetime.now(timezone.utc).isoformat()}")

    print("\nResults summary:")
    for category in (
        "known-cdn",
        "cdn-hints",
        "cloud-hosting",
        "unclassified",
    ):
        print(f"  {category}: {len(categories[category])}")

    print(f"  invalid lines: {len(invalid_lines)}")

    print("\nOutput files:")
    for filename in files:
        print(f"  {filename}")

    print(
        "\n[!] Reminder: unclassified IPs are not confirmed origin IPs. "
        "Verify ownership, DNS history, and authorized exposure separately."
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
