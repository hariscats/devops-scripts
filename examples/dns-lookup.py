#!/usr/bin/env python3
"""
Example: Simple DNS lookup using only the Python standard library.

Resolves one or more hostnames to their IPv4/IPv6 addresses and
performs a reverse lookup on each address.
"""

import argparse
import socket


def lookup(hostname):
    """Print the addresses for a hostname and their reverse DNS names."""
    print(f"{hostname}")
    try:
        results = socket.getaddrinfo(hostname, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        print(f"  lookup failed: {e}")
        return

    addresses = sorted({result[4][0] for result in results})
    for address in addresses:
        try:
            reverse_name = socket.gethostbyaddr(address)[0]
        except (socket.herror, socket.gaierror):
            reverse_name = "no reverse record"
        print(f"  {address:<40} {reverse_name}")


def main():
    """Main execution function."""
    parser = argparse.ArgumentParser(description="Simple DNS lookup tool")
    parser.add_argument("hostnames", nargs="+", help="Hostnames to look up")
    args = parser.parse_args()

    for hostname in args.hostnames:
        lookup(hostname)


if __name__ == "__main__":
    main()
