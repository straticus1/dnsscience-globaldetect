# GlobalDetect

ISP Network Engineering Utilities - A comprehensive CLI toolkit for network engineers providing tools for IP/CIDR management, BGP analysis, DNS utilities, diagnostics, and security intelligence.

## Features

### IP/CIDR Tools (`globaldetect ip`)
- **info** - Get detailed information about an IP address (supports `--geoip` for full geolocation)
- **calc** - Subnet calculator with network/broadcast/usable range
- **split** - Split CIDR blocks into smaller subnets
- **merge** - Merge adjacent CIDR blocks
- **bogon** - Check if an IP is a bogon (reserved/private)
- **contains** - Check if an IP is within a CIDR range

### BGP/Routing (`globaldetect bgp`)
- **asinfo** - Get AS information (name, country, prefixes)
- **prefixes** - List prefixes announced by an AS
- **peers** - Get peering information from PeeringDB
- **whois** - BGP WHOIS lookup

### DNS Utilities (`globaldetect dns`)
- **query** - DNS lookups with any record type
- **propagation** - Check DNS propagation across global resolvers
- **trace** - Trace DNS delegation chain
- **mx** - Mail server lookup with priority
- **reverse** - Reverse DNS (PTR) lookup

### Diagnostics (`globaldetect diag`)
- **ping** - ICMP ping with statistics
- **traceroute** - Network path tracing (supports `--geoip` for geolocation of each hop)
- **mtu** - MTU path discovery
- **port** - TCP port connectivity check

### Reconnaissance (`globaldetect recon`)
- **scan** - Port scanning with service detection
- **ssl** - SSL/TLS certificate analysis and grading
- **profile** - Comprehensive target profiling

### RBL/Blacklist (`globaldetect rbl`)
- **check** - Check IP against 50+ RBL providers
- **batch** - Batch check multiple IPs
- **list** - List all supported RBL providers

Supported providers include: Spamhaus, Barracuda, SpamCop, SORBS, UCEProtect, Proofpoint, SenderBase (Cisco/IronPort), and many more.

### Dark Web Intelligence (`globaldetect darkweb`)
- **tor** - Check if IP is a Tor exit node
- **check** - Comprehensive dark web association check
- **batch** - Batch Tor exit check

### Neighbor Discovery (`globaldetect neighbors`)
- **discover** - Discover neighbors using CDP and LLDP
- **cdp** - Listen for CDP (Cisco Discovery Protocol) v2 frames
- **lldp** - Listen for LLDP (Link Layer Discovery Protocol) frames
- **interfaces** - List available network interfaces

### Packet Capture & Analysis (`globaldetect cap`)
- **capture** - Capture traffic (DNS, SMTP, SSL, BGP, ICMP, etc.)
- **analyze** - Analyze pcap files for L2/L3 issues, protocol errors
- **live** - Real-time packet capture and display
- **protocols** - List available capture filters

Detects: broadcast storms, ARP anomalies, STP issues, ICMP errors, TCP retransmissions, DNS failures, SSL/TLS problems, SMTP errors.

### HTTP Testing (`globaldetect http`)
- **request** - Full-featured HTTP client with JSON/XML support
- **get/post** - Quick HTTP method shortcuts
- **validate** - Test endpoints against expected responses
- **bench** - Simple HTTP benchmark/load test
- **headers** - Inspect response headers and security headers

### External Services (`globaldetect services`)
- **ipinfo** - IPInfo.io lookup
- **abuse** - AbuseIPDB reputation check
- **cloudflare** - Cloudflare DNS and Radar API
- **dnsscience** - DNS Science.io threat intelligence

### Network Inventory (`globaldetect catalog`, `system`, `switch`, `location`)

Full network asset inventory and catalog system supporting SQLite (default) and PostgreSQL (enterprise).

**Discovery (`globaldetect catalog`)**
- **discover** - Scan subnets to discover and catalog systems
- **self** - Discover and report local system information

**System Management (`globaldetect system`)**
- **add** - Add systems with full metadata (hostname, IP, type, location, etc.)
- **list** - List systems with filtering (by type, status, switch, tags)
- **show** - Show detailed system info including switch connectivity
- **update** - Update system properties
- **delete** - Remove systems from inventory
- **search** - Search by hostname, IP, or notes

**Switch Management (`globaldetect switch`)**
- **list** - List network switches
- **show** - Show switch details and connected systems
- **add/delete** - Manage switch inventory

**Location Management (`globaldetect location`)**
- **list** - List datacenters and locations
- **add** - Add datacenter/rack locations
- **rack** - Show systems in a specific rack

**Database (`globaldetect db`)**
- **init** - Initialize database schema
- **stats** - Show inventory statistics

**Features:**
- **Multi-interface support** - Track eth0, eth1, mgmt interfaces with DNS names
- **Interface roles** - Primary, management, storage, backup, cluster, etc.
- **DNS names per interface** - e.g., `eth0.example.com`, `mgmt.example.com`
- **Physical location** - Country, state, city, datacenter, building, floor, rack, U position
- **Switch connectivity** - Track which port each system is plugged into
- **Lifecycle tracking** - Ordered, purchased, shipped, delivered, installed, active, decommissioned
- **Shipping/tracking** - PO numbers, tracking numbers, carrier info
- **Service tickets** - Install ticket, last service ticket, warranty expiration
- **GeoIP enrichment** - Auto-populate country/city from IP
- **Tags and custom fields** - Flexible metadata

### Agent Mode (`globaldetect agent`)
- **run** - Run agent daemon to report system inventory to central server
- **info** - Show what would be reported
- **config** - Generate example configuration

### Inventory Server (`globaldetect server`)
- **run** - Start REST API server for agent check-ins
- **generate-key** - Generate API keys for agents

## Installation

See [INSTALL.md](INSTALL.md) for detailed installation instructions.

### Quick Start

```bash
# Clone the repository
git clone https://github.com/dnsscience/globaldetect.git
cd globaldetect

# Create virtual environment (requires Python 3.10+)
python3 -m venv venv
source venv/bin/activate

# Install in development mode
pip install -e .

# Run
globaldetect --help
```

## Configuration

GlobalDetect uses environment variables for API keys. Create a `.env` file or export them:

```bash
export IPINFO_TOKEN="your_token"
export ABUSEIPDB_API_KEY="your_key"
export CLOUDFLARE_API_TOKEN="your_token"
export DNSSCIENCE_API_KEY="your_key"
```

## Usage Examples

```bash
# IP Information
globaldetect ip info 8.8.8.8
globaldetect ip info 8.8.8.8 --geoip      # Include full GeoIP data
globaldetect ip calc 10.0.0.0/24
globaldetect ip bogon 192.168.1.1

# BGP Analysis
globaldetect bgp asinfo 15169
globaldetect bgp prefixes 15169
globaldetect bgp peers 15169

# DNS Utilities
globaldetect dns query google.com
globaldetect dns propagation example.com --type A
globaldetect dns trace example.com

# Diagnostics
globaldetect diag ping 8.8.8.8
globaldetect diag trace google.com
globaldetect diag trace 1.1.1.1 --geoip   # Traceroute with GeoIP for each hop
globaldetect diag port 8.8.8.8 443

# Reconnaissance
globaldetect recon scan 192.168.1.1 --ports 22,80,443
globaldetect recon ssl google.com
globaldetect recon profile example.com

# RBL/Blacklist
globaldetect rbl check 1.2.3.4
globaldetect rbl batch 1.2.3.4 5.6.7.8

# Dark Web Intelligence
globaldetect darkweb tor 185.220.101.1
globaldetect darkweb check suspicious-domain.com

# Neighbor Discovery (requires root/sudo)
sudo globaldetect neighbors discover           # Listen for CDP and LLDP
sudo globaldetect neighbors cdp -i eth0        # CDP only on eth0
sudo globaldetect neighbors lldp -t 60         # LLDP with 60s timeout
globaldetect neighbors interfaces              # List available interfaces

# Packet Capture & Analysis (requires root/sudo)
sudo globaldetect cap capture dns -t 5m        # Capture DNS traffic for 5 minutes
sudo globaldetect cap capture email -t 10m -o email.pcap
sudo globaldetect cap analyze -f capture.pcap  # Analyze for network issues
sudo globaldetect cap live icmp -t 30s         # Live ICMP monitoring
globaldetect cap protocols                     # List available capture filters

# HTTP Testing
globaldetect http get https://api.example.com/users
globaldetect http post https://api.example.com/data --json '{"key": "value"}'
globaldetect http request https://api.example.com -H "Authorization: Bearer token"
globaldetect http validate https://api.example.com/health --status 200
globaldetect http bench https://api.example.com -n 100 -c 10
globaldetect http headers https://www.example.com

# Network Inventory - Discovery
globaldetect catalog discover 192.168.1.0/24           # Scan subnet
globaldetect catalog discover 192.168.1.0/24 --save    # Scan and save to inventory
globaldetect catalog discover 10.0.0.1 --type host     # Single host
globaldetect catalog self --save                       # Discover and save this system

# Network Inventory - System Management
globaldetect system list                               # List all systems
globaldetect system list --type server --status active # Filter by type/status
globaldetect system list --switch core-sw01           # Systems on a switch
globaldetect system show webserver01                  # Show system details
globaldetect system show webserver01 --switch         # Include switch connectivity
globaldetect system show webserver01 --network        # Show all interfaces
globaldetect system add --hostname db01 --ip 10.0.0.50 --type server \
    --datacenter DC1 --rack A15 --rack-unit 20
globaldetect system update db01 --status maintenance --note "Disk replacement"
globaldetect system search "web"                      # Search by hostname/IP/notes

# Network Inventory - Switch Management
globaldetect switch list
globaldetect switch show core-sw01 --systems          # Show connected systems
globaldetect switch add --hostname core-sw01 --ip 10.0.0.1 --vendor Cisco \
    --model "Nexus 9000" --ports 48 --datacenter DC1 --rack A01

# Network Inventory - Location Management
globaldetect location list
globaldetect location add --datacenter DC1 --rack A15 --city "New York" --country US
globaldetect location rack A15 --datacenter DC1       # Show systems in rack

# Network Inventory - Database
globaldetect db init                                  # Initialize database
globaldetect db stats                                 # Show statistics

# Use PostgreSQL instead of SQLite
export GLOBALDETECT_DB="postgresql://user:pass@host/inventory"
globaldetect db init

# Agent Mode - Report system to central server
globaldetect agent info                               # Show what would be reported
globaldetect agent config --output /etc/globaldetect/agent.conf
globaldetect agent run --server https://inventory.example.com --api-key KEY
globaldetect agent run --config /etc/globaldetect/agent.conf

# Inventory Server - Central API
globaldetect server run                               # Start on port 8080
globaldetect server run --port 9000 --db postgresql://localhost/inventory
globaldetect server generate-key                      # Generate agent API key
```

## Requirements

- Python 3.10+
- Dependencies: click, netaddr, dnspython, rich, httpx, python-dotenv

## License

MIT License - Copyright (c) 2025 DNS Science.io, an After Dark Systems, LLC company.

See [LICENSE](LICENSE) for details.

## Contributing

Contributions are welcome! Please read our contributing guidelines and submit pull requests.

## Support

- GitHub Issues: https://github.com/dnsscience/globaldetect/issues
- Documentation: https://dnsscience.io/docs/globaldetect
