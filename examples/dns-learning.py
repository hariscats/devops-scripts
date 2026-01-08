#!/usr/bin/env python3
"""
DNS Learning Script - Understanding DNS Beyond the Basics.

This script provides an interactive way to learn about DNS (Domain Name System)
by demonstrating various DNS concepts, record types, and resolution processes.

Topics covered:
- DNS record types (A, AAAA, MX, TXT, CNAME, NS, SOA, PTR, etc.)
- DNS resolution hierarchy (root servers, TLD servers, authoritative servers)
- Recursive vs iterative queries
- DNS caching and TTL (Time To Live)
- Reverse DNS lookups
- DNSSEC basics
- DNS debugging techniques
"""

import argparse
import socket
import sys
import time
from typing import Any, Dict, List, Optional

try:
    import dns.resolver
    import dns.reversename
    import dns.query
    import dns.zone
    import dns.name
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("Warning: dnspython not installed. Install with: pip install dnspython")

# Try to import devops_tools logging, fall back to standard logging
try:
    from devops_tools.common.utils import setup_logging
except ImportError:
    import logging
    def setup_logging(level="INFO"):
        """Fallback logging setup if devops_tools is not available."""
        logging.basicConfig(
            level=getattr(logging, level),
            format='%(message)s'
        )
        return logging.getLogger(__name__)


class DNSLearner:
    """Interactive DNS learning tool."""

    def __init__(self, logger):
        """Initialize the DNS learner."""
        self.logger = logger
        if DNS_AVAILABLE:
            # Create resolver and configure with public DNS servers
            self.resolver = dns.resolver.Resolver(configure=False)
            # Use Google's public DNS for consistent results
            self.resolver.nameservers = ['8.8.8.8', '8.8.4.4']

    def demonstrate_record_types(self, domain: str = "google.com"):
        """
        Demonstrate different DNS record types.

        DNS Record Types Explained:
        - A: IPv4 address mapping (domain -> IPv4)
        - AAAA: IPv6 address mapping (domain -> IPv6)
        - MX: Mail exchanger (where to send email for this domain)
        - TXT: Text records (SPF, DKIM, verification, etc.)
        - CNAME: Canonical name (alias to another domain)
        - NS: Name server (authoritative DNS servers for domain)
        - SOA: Start of Authority (primary info about DNS zone)
        - PTR: Pointer record (reverse DNS, IP -> domain)
        - SRV: Service record (location of services)
        """
        if not DNS_AVAILABLE:
            self.logger.error("dnspython is required for this demonstration")
            return

        self.logger.info(f"\n{'='*70}")
        self.logger.info("DNS RECORD TYPES DEMONSTRATION")
        self.logger.info(f"{'='*70}\n")
        self.logger.info(f"Querying domain: {domain}\n")

        # Record types to query
        record_types = {
            'A': 'IPv4 Address - Maps domain to IPv4 address',
            'AAAA': 'IPv6 Address - Maps domain to IPv6 address',
            'MX': 'Mail Exchange - Defines mail servers for domain',
            'TXT': 'Text Records - Arbitrary text, often used for verification',
            'NS': 'Name Servers - Authoritative DNS servers for this domain',
            'SOA': 'Start of Authority - Primary DNS zone information',
            'CNAME': 'Canonical Name - Alias to another domain',
        }

        for record_type, description in record_types.items():
            self.logger.info(f"--- {record_type} Record ---")
            self.logger.info(f"Purpose: {description}")

            try:
                answers = self.resolver.resolve(domain, record_type)
                self.logger.info(f"Found {len(answers)} {record_type} record(s):")

                for rdata in answers:
                    if record_type == 'MX':
                        self.logger.info(f"  Priority: {rdata.preference}, Mail Server: {rdata.exchange}")
                    elif record_type == 'SOA':
                        self.logger.info(f"  Primary NS: {rdata.mname}")
                        self.logger.info(f"  Admin Email: {rdata.rname}")
                        self.logger.info(f"  Serial: {rdata.serial}")
                        self.logger.info(f"  Refresh: {rdata.refresh}s")
                        self.logger.info(f"  Retry: {rdata.retry}s")
                        self.logger.info(f"  Expire: {rdata.expire}s")
                        self.logger.info(f"  Minimum TTL: {rdata.minimum}s")
                    elif record_type == 'TXT':
                        # TXT records can be long, truncate if needed
                        txt_value = str(rdata).strip('"')
                        if len(txt_value) > 100:
                            txt_value = txt_value[:100] + "..."
                        self.logger.info(f"  {txt_value}")
                    else:
                        self.logger.info(f"  {rdata}")

                # Show TTL (Time To Live) - how long to cache this record
                self.logger.info(f"TTL: {answers.rrset.ttl} seconds (cache for this long)")

            except dns.resolver.NoAnswer:
                self.logger.info(f"  No {record_type} records found")
            except dns.resolver.NXDOMAIN:
                self.logger.error(f"  Domain {domain} does not exist")
                break
            except Exception as e:
                self.logger.error(f"  Error querying {record_type}: {e}")

            self.logger.info("")

    def demonstrate_dns_hierarchy(self, domain: str = "www.example.com"):
        """
        Demonstrate DNS resolution hierarchy.

        DNS Hierarchy (from top to bottom):
        1. Root DNS Servers (.) - 13 root server systems worldwide
        2. TLD DNS Servers (.com, .org, .net, etc.)
        3. Authoritative DNS Servers (specific to the domain)

        Resolution Process:
        - Recursive: DNS resolver does all the work for you
        - Iterative: You follow referrals yourself from each level
        """
        if not DNS_AVAILABLE:
            self.logger.error("dnspython is required for this demonstration")
            return

        self.logger.info(f"\n{'='*70}")
        self.logger.info("DNS HIERARCHY AND RESOLUTION PROCESS")
        self.logger.info(f"{'='*70}\n")

        self.logger.info("DNS Resolution Hierarchy for: " + domain)
        self.logger.info("\nThe DNS system is hierarchical, like a tree:\n")

        # Parse domain into parts
        parts = domain.split('.')
        self.logger.info("Domain breakdown:")
        for i, part in enumerate(reversed(parts)):
            indent = "  " * i
            if i == 0:
                self.logger.info(f"{indent}Root (.) - Top of hierarchy")
            elif i == len(parts) - 1:
                self.logger.info(f"{indent}'{part}' - Hostname/subdomain")
            else:
                self.logger.info(f"{indent}'{part}' - Domain level {i}")

        self.logger.info("\n--- Root DNS Servers ---")
        self.logger.info("There are 13 root server systems (A-M) that know about TLD servers:")
        # Show a few root servers
        root_servers = ['a.root-servers.net', 'b.root-servers.net', 'c.root-servers.net']
        for root in root_servers:
            try:
                ip = socket.gethostbyname(root)
                self.logger.info(f"  {root} -> {ip}")
            except Exception:
                self.logger.info(f"  {root}")
        self.logger.info("  ... and j.root-servers.net through m.root-servers.net")

        self.logger.info("\n--- Authoritative Name Servers ---")
        self.logger.info(f"Name servers that authoritatively answer for {domain}:")
        try:
            answers = self.resolver.resolve(domain, 'NS')
            for ns in answers:
                ns_name = str(ns.target)
                self.logger.info(f"  {ns_name}")
                # Try to get IP of nameserver
                try:
                    ns_ip = socket.gethostbyname(ns_name)
                    self.logger.info(f"    -> {ns_ip}")
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"  Could not retrieve NS records: {e}")

        self.logger.info("\n--- Resolution Types ---")
        self.logger.info("1. Recursive Query (typical):")
        self.logger.info("   Client -> Resolver: 'What is www.example.com?'")
        self.logger.info("   Resolver does all the work:")
        self.logger.info("   - Asks root server: 'Where are .com servers?'")
        self.logger.info("   - Asks .com server: 'Where are example.com servers?'")
        self.logger.info("   - Asks example.com server: 'What is www.example.com?'")
        self.logger.info("   Resolver -> Client: 'Here's the IP address'")

        self.logger.info("\n2. Iterative Query:")
        self.logger.info("   Client asks each server in the chain itself")
        self.logger.info("   Each server says 'I don't know, but ask this other server'")
        self.logger.info("   More work for client, but shows the full hierarchy")

    def demonstrate_ttl_and_caching(self, domain: str = "google.com"):
        """
        Demonstrate DNS caching and TTL (Time To Live).

        TTL (Time To Live):
        - Specifies how long (in seconds) a DNS record can be cached
        - Shorter TTL = more DNS queries, more up-to-date
        - Longer TTL = fewer DNS queries, faster, but changes take longer to propagate
        - Typical values: 300s (5 min) to 86400s (24 hours)
        """
        if not DNS_AVAILABLE:
            self.logger.error("dnspython is required for this demonstration")
            return

        self.logger.info(f"\n{'='*70}")
        self.logger.info("DNS CACHING AND TTL (TIME TO LIVE)")
        self.logger.info(f"{'='*70}\n")

        self.logger.info("TTL controls how long DNS records are cached\n")

        self.logger.info(f"Querying {domain} multiple times to observe TTL...")

        for query_num in range(1, 4):
            self.logger.info(f"\n--- Query #{query_num} ---")
            try:
                start_time = time.time()
                answers = self.resolver.resolve(domain, 'A')
                query_time = (time.time() - start_time) * 1000  # Convert to ms

                self.logger.info(f"Query time: {query_time:.2f} ms")
                self.logger.info(f"TTL: {answers.rrset.ttl} seconds")
                self.logger.info(f"IP Address: {answers[0]}")

                if query_num == 1:
                    initial_ttl = answers.rrset.ttl
                    self.logger.info(f"\nThis record can be cached for {initial_ttl} seconds")
                    self.logger.info("Subsequent queries may be faster if cached locally")

                if query_num < 3:
                    time.sleep(1)  # Wait a second between queries

            except Exception as e:
                self.logger.error(f"Error querying: {e}")

        self.logger.info("\n--- Cache Benefits ---")
        self.logger.info("Caching reduces:")
        self.logger.info("  • DNS query latency (faster page loads)")
        self.logger.info("  • Load on DNS servers")
        self.logger.info("  • Network traffic")

        self.logger.info("\n--- TTL Strategy ---")
        self.logger.info("Low TTL (300s - 5 min):")
        self.logger.info("  ✓ Use when planning DNS changes")
        self.logger.info("  ✓ Faster failover/disaster recovery")
        self.logger.info("  ✗ More DNS traffic")

        self.logger.info("\nHigh TTL (86400s - 24 hours):")
        self.logger.info("  ✓ Reduced DNS load and faster response")
        self.logger.info("  ✓ Better for stable infrastructure")
        self.logger.info("  ✗ Changes take longer to propagate")

    def demonstrate_reverse_dns(self, ip: str = "8.8.8.8"):
        """
        Demonstrate reverse DNS lookups (PTR records).

        Reverse DNS:
        - Maps IP address -> domain name (opposite of normal DNS)
        - Uses special domain: in-addr.arpa for IPv4
        - Format: reverse IP + .in-addr.arpa
        - Example: 8.8.8.8 -> 8.8.8.8.in-addr.arpa
        - Used for email verification, logging, security
        """
        if not DNS_AVAILABLE:
            self.logger.error("dnspython is required for this demonstration")
            return

        self.logger.info(f"\n{'='*70}")
        self.logger.info("REVERSE DNS LOOKUP (PTR Records)")
        self.logger.info(f"{'='*70}\n")

        self.logger.info("Reverse DNS: IP Address -> Domain Name\n")
        self.logger.info(f"Looking up: {ip}\n")

        try:
            # Create reverse DNS name
            rev_name = dns.reversename.from_address(ip)
            self.logger.info(f"Reverse DNS query name: {rev_name}")

            # Perform reverse lookup
            answers = self.resolver.resolve(rev_name, 'PTR')

            self.logger.info(f"\nReverse DNS results for {ip}:")
            for rdata in answers:
                self.logger.info(f"  -> {rdata}")

            # Now do forward lookup to verify
            domain = str(answers[0]).rstrip('.')
            self.logger.info(f"\n--- Verification: Forward Lookup ---")
            self.logger.info(f"Resolving {domain} back to IP...")
            forward = self.resolver.resolve(domain, 'A')
            for rdata in forward:
                match = "✓ MATCH" if str(rdata) == ip else "✗ DIFFERENT"
                self.logger.info(f"  {rdata} {match}")

        except dns.resolver.NXDOMAIN:
            self.logger.warning(f"No reverse DNS record found for {ip}")
        except Exception as e:
            self.logger.error(f"Error performing reverse lookup: {e}")

        self.logger.info("\n--- Reverse DNS Uses ---")
        self.logger.info("• Email servers: Verify sender identity (anti-spam)")
        self.logger.info("• Logging: Convert IPs to hostnames in logs")
        self.logger.info("• Network troubleshooting: Identify devices")
        self.logger.info("• Security: Validate server authenticity")

    def demonstrate_dns_debugging(self, domain: str = "github.com"):
        """
        Demonstrate DNS debugging techniques.

        DNS Debugging Tools:
        - dig: Detailed DNS query tool (Linux/Mac)
        - nslookup: Cross-platform DNS query tool
        - host: Simple DNS lookup tool
        - Python's dnspython library
        """
        if not DNS_AVAILABLE:
            self.logger.error("dnspython is required for this demonstration")
            return

        self.logger.info(f"\n{'='*70}")
        self.logger.info("DNS DEBUGGING TECHNIQUES")
        self.logger.info(f"{'='*70}\n")

        self.logger.info(f"Debugging DNS for: {domain}\n")

        # 1. Check response flags
        self.logger.info("--- DNS Response Analysis ---")
        try:
            answers = self.resolver.resolve(domain, 'A')

            self.logger.info(f"Response Details:")
            self.logger.info(f"  Records returned: {len(answers)}")
            self.logger.info(f"  TTL: {answers.rrset.ttl}s")
            self.logger.info(f"  Canonical name: {answers.canonical_name}")

            for i, rdata in enumerate(answers, 1):
                self.logger.info(f"  Answer {i}: {rdata}")

        except Exception as e:
            self.logger.error(f"Error: {e}")

        # 2. Query multiple record types
        self.logger.info("\n--- Multi-Record Type Check ---")
        check_types = ['A', 'AAAA', 'MX', 'TXT']
        for rtype in check_types:
            try:
                answers = self.resolver.resolve(domain, rtype)
                self.logger.info(f"  {rtype}: {len(answers)} record(s) found")
            except dns.resolver.NoAnswer:
                self.logger.info(f"  {rtype}: No records")
            except Exception:
                self.logger.info(f"  {rtype}: Query failed")

        # 3. Check different DNS servers
        self.logger.info("\n--- Querying Different DNS Servers ---")
        dns_servers = {
            'Google': '8.8.8.8',
            'Cloudflare': '1.1.1.1',
            'Quad9': '9.9.9.9',
        }

        for name, server in dns_servers.items():
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server]
            resolver.timeout = 2
            resolver.lifetime = 2

            try:
                start = time.time()
                answers = resolver.resolve(domain, 'A')
                elapsed = (time.time() - start) * 1000
                self.logger.info(f"  {name} ({server}): {answers[0]} ({elapsed:.0f}ms)")
            except Exception as e:
                self.logger.info(f"  {name} ({server}): Failed - {e}")

        self.logger.info("\n--- Common DNS Issues ---")
        issues = [
            "NXDOMAIN: Domain doesn't exist",
            "SERVFAIL: DNS server encountered an error",
            "REFUSED: Server refused the query",
            "Timeout: Server didn't respond (firewall, network issue)",
            "No answer: Record type doesn't exist for domain",
        ]
        for issue in issues:
            self.logger.info(f"  • {issue}")

    def demonstrate_dnssec_basics(self, domain: str = "cloudflare.com"):
        """
        Demonstrate DNSSEC (DNS Security Extensions) basics.

        DNSSEC:
        - Adds cryptographic signatures to DNS records
        - Prevents DNS spoofing/cache poisoning
        - Provides authentication (data came from authoritative source)
        - Uses DNSKEY, RRSIG, DS, and NSEC/NSEC3 records
        - Establishes chain of trust from root to domain
        """
        if not DNS_AVAILABLE:
            self.logger.error("dnspython is required for this demonstration")
            return

        self.logger.info(f"\n{'='*70}")
        self.logger.info("DNSSEC (DNS Security Extensions) BASICS")
        self.logger.info(f"{'='*70}\n")

        self.logger.info("DNSSEC adds cryptographic signatures to DNS records\n")

        self.logger.info(f"Checking DNSSEC for: {domain}\n")

        # Check for DNSSEC-related records
        dnssec_records = {
            'DNSKEY': 'Public keys used to verify signatures',
            'RRSIG': 'Cryptographic signatures of record sets',
            'DS': 'Delegation Signer - links parent to child zone',
            'NSEC': 'Authenticated denial of existence',
        }

        for record_type, description in dnssec_records.items():
            self.logger.info(f"--- {record_type} ---")
            self.logger.info(f"Purpose: {description}")
            try:
                answers = self.resolver.resolve(domain, record_type)
                self.logger.info(f"  ✓ {len(answers)} {record_type} record(s) found")
                if record_type == 'DNSKEY':
                    for rdata in answers:
                        flags = rdata.flags
                        key_type = "ZSK (Zone Signing Key)" if flags == 256 else "KSK (Key Signing Key)" if flags == 257 else f"Unknown (flags={flags})"
                        self.logger.info(f"    Key: {key_type}")
            except dns.resolver.NoAnswer:
                self.logger.info(f"  ✗ No {record_type} records (DNSSEC may not be enabled)")
            except Exception as e:
                self.logger.info(f"  Error: {e}")
            self.logger.info("")

        self.logger.info("--- DNSSEC Benefits ---")
        benefits = [
            "Prevents DNS spoofing and cache poisoning",
            "Authenticates DNS responses",
            "Ensures data integrity",
            "Establishes chain of trust",
        ]
        for benefit in benefits:
            self.logger.info(f"  ✓ {benefit}")

        self.logger.info("\n--- DNSSEC Limitations ---")
        limitations = [
            "Doesn't provide confidentiality (DNS queries still visible)",
            "Adds complexity to DNS infrastructure",
            "Requires careful key management",
            "Not universally deployed",
        ]
        for limitation in limitations:
            self.logger.info(f"  • {limitation}")

    def demonstrate_all(self):
        """Run all demonstrations with default domains."""
        self.logger.info("\n" + "="*70)
        self.logger.info(" DNS LEARNING SCRIPT - COMPREHENSIVE DEMONSTRATION")
        self.logger.info("="*70)

        demos = [
            ("Record Types", lambda: self.demonstrate_record_types("google.com")),
            ("DNS Hierarchy", lambda: self.demonstrate_dns_hierarchy("www.example.com")),
            ("TTL and Caching", lambda: self.demonstrate_ttl_and_caching("google.com")),
            ("Reverse DNS", lambda: self.demonstrate_reverse_dns("8.8.8.8")),
            ("DNS Debugging", lambda: self.demonstrate_dns_debugging("github.com")),
            ("DNSSEC Basics", lambda: self.demonstrate_dnssec_basics("cloudflare.com")),
        ]

        for name, demo_func in demos:
            try:
                demo_func()
                time.sleep(1)  # Brief pause between sections
            except KeyboardInterrupt:
                self.logger.info("\nDemonstration interrupted by user")
                sys.exit(0)
            except Exception as e:
                self.logger.error(f"Error in {name} demonstration: {e}")

        self.logger.info("\n" + "="*70)
        self.logger.info(" DEMONSTRATION COMPLETE")
        self.logger.info("="*70)
        self.logger.info("\nKey Takeaways:")
        self.logger.info("  • DNS is hierarchical (root -> TLD -> authoritative)")
        self.logger.info("  • Multiple record types serve different purposes")
        self.logger.info("  • TTL controls caching behavior")
        self.logger.info("  • Reverse DNS maps IPs to domains")
        self.logger.info("  • DNSSEC adds security through cryptographic signatures")
        self.logger.info("\nFor more learning, try:")
        self.logger.info("  • Run with --domain <your-domain> to explore specific domains")
        self.logger.info("  • Use --demo <type> to focus on specific concepts")
        self.logger.info("  • Read RFC 1034, 1035 (DNS), RFC 4033-4035 (DNSSEC)")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(
        description="DNS Learning Script - Interactive DNS education tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all demonstrations
  %(prog)s --all

  # Demonstrate DNS record types
  %(prog)s --demo records --domain example.com

  # Show DNS hierarchy
  %(prog)s --demo hierarchy --domain www.github.com

  # Learn about caching and TTL
  %(prog)s --demo cache --domain google.com

  # Reverse DNS lookup
  %(prog)s --demo reverse --ip 1.1.1.1

  # DNS debugging techniques
  %(prog)s --demo debug --domain cloudflare.com

  # DNSSEC basics
  %(prog)s --demo dnssec --domain cloudflare.com
        """
    )

    parser.add_argument(
        '--demo',
        choices=['records', 'hierarchy', 'cache', 'reverse', 'debug', 'dnssec'],
        help='Run specific demonstration'
    )
    parser.add_argument(
        '--domain',
        default='google.com',
        help='Domain name to use for demonstrations (default: google.com)'
    )
    parser.add_argument(
        '--ip',
        default='8.8.8.8',
        help='IP address for reverse DNS lookup (default: 8.8.8.8)'
    )
    parser.add_argument(
        '--all',
        action='store_true',
        help='Run all demonstrations'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose output'
    )

    args = parser.parse_args()

    # Set up logging
    log_level = "DEBUG" if args.verbose else "INFO"
    logger = setup_logging(level=log_level)

    if not DNS_AVAILABLE:
        logger.error("This script requires the 'dnspython' library")
        logger.error("Install it with: pip install dnspython")
        sys.exit(1)

    # Initialize learner
    learner = DNSLearner(logger)

    try:
        if args.all:
            learner.demonstrate_all()
        elif args.demo == 'records':
            learner.demonstrate_record_types(args.domain)
        elif args.demo == 'hierarchy':
            learner.demonstrate_dns_hierarchy(args.domain)
        elif args.demo == 'cache':
            learner.demonstrate_ttl_and_caching(args.domain)
        elif args.demo == 'reverse':
            learner.demonstrate_reverse_dns(args.ip)
        elif args.demo == 'debug':
            learner.demonstrate_dns_debugging(args.domain)
        elif args.demo == 'dnssec':
            learner.demonstrate_dnssec_basics(args.domain)
        else:
            # Default: show help
            parser.print_help()
            logger.info("\nTip: Use --all to run all demonstrations")

    except KeyboardInterrupt:
        logger.info("\nScript interrupted by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Unexpected error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
