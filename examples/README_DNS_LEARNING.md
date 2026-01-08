# DNS Learning Script

An interactive educational tool to help you understand DNS (Domain Name System) beyond the basics.

## Overview

This script provides hands-on demonstrations of various DNS concepts including:

- **DNS Record Types**: A, AAAA, MX, TXT, CNAME, NS, SOA, PTR
- **DNS Hierarchy**: Root servers, TLD servers, authoritative servers
- **DNS Resolution**: Recursive vs iterative queries
- **Caching & TTL**: How DNS caching works and Time To Live
- **Reverse DNS**: IP-to-domain lookups (PTR records)
- **DNSSEC**: DNS security extensions basics
- **DNS Debugging**: Techniques for troubleshooting DNS issues

## Installation

### Prerequisites

```bash
# Install dnspython library
pip install dnspython>=2.4.0

# Or install all project dependencies
pip install -r requirements.txt
```

### Making the Script Executable

```bash
chmod +x examples/dns-learning.py
```

## Usage

### Run All Demonstrations

Get a comprehensive overview of all DNS concepts:

```bash
python examples/dns-learning.py --all
```

### Run Specific Demonstrations

#### 1. DNS Record Types

Learn about different DNS record types (A, AAAA, MX, TXT, etc.):

```bash
python examples/dns-learning.py --demo records --domain google.com
```

**What you'll learn:**
- What each record type does
- How to query different record types
- Understanding TTL values
- Real-world examples

#### 2. DNS Hierarchy

Understand the hierarchical structure of DNS:

```bash
python examples/dns-learning.py --demo hierarchy --domain www.example.com
```

**What you'll learn:**
- Root DNS servers
- TLD (Top Level Domain) servers
- Authoritative nameservers
- Recursive vs iterative queries

#### 3. DNS Caching and TTL

See how DNS caching works:

```bash
python examples/dns-learning.py --demo cache --domain google.com
```

**What you'll learn:**
- What TTL (Time To Live) means
- How caching improves performance
- When to use high vs low TTL values
- Cache behavior over multiple queries

#### 4. Reverse DNS Lookups

Learn about IP-to-domain resolution:

```bash
python examples/dns-learning.py --demo reverse --ip 8.8.8.8
```

**What you'll learn:**
- How reverse DNS works
- PTR records and in-addr.arpa
- Use cases (email verification, logging)
- Forward lookup verification

#### 5. DNS Debugging

Master DNS troubleshooting techniques:

```bash
python examples/dns-learning.py --demo debug --domain github.com
```

**What you'll learn:**
- How to analyze DNS responses
- Querying multiple record types
- Testing different DNS servers
- Common DNS errors and issues

#### 6. DNSSEC Basics

Understand DNS security extensions:

```bash
python examples/dns-learning.py --demo dnssec --domain cloudflare.com
```

**What you'll learn:**
- DNSSEC record types (DNSKEY, RRSIG, DS, NSEC)
- How DNSSEC prevents DNS spoofing
- Chain of trust concept
- Benefits and limitations

## Examples

### Explore Your Own Domain

```bash
# Check your domain's DNS records
python examples/dns-learning.py --demo records --domain yourdomain.com

# See your domain's DNS hierarchy
python examples/dns-learning.py --demo hierarchy --domain www.yourdomain.com
```

### Investigate an IP Address

```bash
# Reverse lookup for any IP
python examples/dns-learning.py --demo reverse --ip 1.1.1.1

# Check Cloudflare's DNS
python examples/dns-learning.py --demo reverse --ip 1.0.0.1
```

### Compare DNS Providers

```bash
# Google's DNS
python examples/dns-learning.py --demo debug --domain google.com

# Cloudflare's DNS
python examples/dns-learning.py --demo debug --domain cloudflare.com
```

## Command-Line Options

```
--demo {records,hierarchy,cache,reverse,debug,dnssec}
    Run a specific demonstration

--domain DOMAIN
    Domain name to use (default: google.com)

--ip IP
    IP address for reverse DNS (default: 8.8.8.8)

--all
    Run all demonstrations sequentially

-v, --verbose
    Enable verbose/debug output

-h, --help
    Show help message
```

## Key Concepts Covered

### DNS Record Types

| Record | Purpose | Example |
|--------|---------|---------|
| A | IPv4 address | `example.com -> 93.184.216.34` |
| AAAA | IPv6 address | `example.com -> 2606:2800:220:1:...` |
| MX | Mail server | `example.com -> mail.example.com` |
| TXT | Text data | SPF, DKIM, verification tokens |
| CNAME | Alias | `www.example.com -> example.com` |
| NS | Name server | Authoritative DNS servers |
| SOA | Zone authority | Primary DNS server info |
| PTR | Reverse DNS | `8.8.8.8 -> dns.google` |

### DNS Resolution Process

1. **Client queries resolver** (usually your ISP or public DNS)
2. **Resolver queries root server** for TLD information
3. **Resolver queries TLD server** for authoritative nameserver
4. **Resolver queries authoritative nameserver** for final answer
5. **Resolver returns result** to client and caches it

### TTL Guidelines

- **Low TTL (300s - 5 min)**: When planning changes, need fast failover
- **Medium TTL (3600s - 1 hour)**: Balanced approach
- **High TTL (86400s - 24 hours)**: Stable infrastructure, reduce load

## Troubleshooting

### "dnspython not installed"

```bash
pip install dnspython
```

### "No nameservers" error

The script automatically configures Google's public DNS (8.8.8.8, 8.8.4.4).
If you still see this error, check your network connectivity.

### DNS queries timing out

- Check firewall rules (allow outbound UDP port 53)
- Verify network connectivity
- Try different DNS servers by modifying the script

### "No module named 'devops_tools'"

The script includes a fallback for standalone usage. It will use basic Python logging if the devops_tools module isn't installed.

## Learning Path

Recommended order for beginners:

1. Start with `--demo records` to understand basic record types
2. Move to `--demo hierarchy` to see how DNS is structured
3. Try `--demo cache` to understand performance optimization
4. Experiment with `--demo reverse` for IP lookups
5. Use `--demo debug` to practice troubleshooting
6. Finally, explore `--demo dnssec` for security concepts

## Further Reading

- **RFC 1034**: Domain Names - Concepts and Facilities
- **RFC 1035**: Domain Names - Implementation and Specification
- **RFC 4033-4035**: DNSSEC specifications
- [DNS Made Easy](https://dnsmadeeasy.com/support/dns-guides/)
- [Cloudflare DNS Learning Center](https://www.cloudflare.com/learning/dns/what-is-dns/)

## Contributing

Found an issue or want to add more demonstrations? Feel free to contribute!

## Author

Part of the DevOps Tools collection by **Hariscats**
