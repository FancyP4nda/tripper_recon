<div align="center">

# Tripper Recon

**A high-performance, asynchronous OSINT toolkit for IP, Domain, URL, and ASN investigations.**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

</div>

---

## Overview

Tripper Recon is a powerful, async-first Open Source Intelligence (OSINT) tool designed to streamline infrastructure investigations. Whether you are hunting for threat actors, reviewing SIEM logs, or profiling external IP addresses, Tripper provides a unified interface to query multiple high-tier intelligence providers concurrently. 

Designed with both ease of use and programmatic integration in mind, Tripper Recon offers a fast CLI for analysts and a scalable REST API for automated pipelines.

## Key Features

- **Concurrent Orchestration**: Query multiple providers (VirusTotal, Cloudflare Radar, Shodan, AbuseIPDB, IPInfo, OTX) simultaneously.
- **Async & HTTP/2 First**: Built on `httpx` with connection pooling to maximize throughput and minimize latency. 
- **Resilient Engine**: Features built-in jittered exponential backoff for handling rate limits (`429 Too Many Requests`) elegantly.
- **Dual Interfaces**: Use the lightning-fast CLI for ad-hoc terminal work, or launch the FastAPI server for programmatic REST integration.
- **Enterprise Ready Output**: Clean, borderless console tables powered by `rich` for immediate markdown reporting, alongside structured JSON logging for SIEM ingestion.

---

## Installation

Tripper Recon requires **Python 3.10+**.

```bash
# Clone the repository
git clone https://github.com/FancyP4nda/tripper_recon.git
cd tripper_recon

# Install using pip (recommended to use a virtual environment)
pip install .
```

---

## Quick Start

### CLI

The `tripper-recon` CLI provides immediate, readable intelligence straight to your terminal.

```bash
# Investigate a single IP address
tripper-recon ip 8.8.8.8

# Investigate a domain (automatically resolves IPs)
tripper-recon domain www.cloudflare.com

# Deep-dive into an Autonomous System Number (ASN)
tripper-recon asn 15169
```

**Bulk Processing**: Feed the tool a text file of targets for mass concurrent processing.
```bash
tripper-recon ip ./path/to/suspicious_ips.txt --format json
```

### REST API

Launch the built-in FastAPI server for programmatic access:

```bash
tripper-recon-api
```
*The API interface includes automatic interactive documentation (Swagger UI/ReDoc) out of the box.*

---

## Data Providers

Tripper Recon actively correlates data from the following industry-leading sources:

- **[Cloudflare Radar](https://radar.cloudflare.com/)**: ASN metadata, routing, and BGP prefixes.
- **[VirusTotal v3](https://www.virustotal.com/)**: Detections, reputation scores, passive DNS, and Whois.
- **[Shodan](https://www.shodan.io/)**: Open ports, service banners, and SSL certificate fingerprints.
- **[AbuseIPDB](https://www.abuseipdb.com/)**: Fraud and abuse confidence scoring.
- **[IPInfo](https://ipinfo.io/)**: Core geolocation and network ownership details.
- **[AlienVault OTX](https://otx.alienvault.com/)**: Pulse counts and associated threat intelligence.

---

## Configuration

API access requires configuring your provider keys. Create a `.env` file in the project root:

```ini
# Core
TRIPPER_RECON_LOG_LEVEL=INFO
TRIPPER_RECON_USER_AGENT="Your Custom User Agent"

# Provider Keys
CLOUDFLARE_API_TOKEN=your_token_here
VT_API_KEY=your_key_here
SHODAN_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
IPINFO_TOKEN=your_token_here
OTX_API_KEY=your_key_here
```
*(An example template is provided in `.env.example`)*


