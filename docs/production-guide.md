# eBPF-Shield: Production Deployment Guide

## Overview

eBPF-Shield attaches an XDP program to a network interface and enforces two firewall policies at the driver level, before traffic reaches the Linux networking stack:

1. **IP Blacklist** — unconditionally drops traffic from specified IPs/CIDRs
2. **Port ACL** — for protected TCP ports, silently drops all traffic except from explicitly allowed source IPs ("port hiding")

Processing happens in the XDP hook at driver receive time, achieving line-rate packet filtering with minimal CPU impact even under high load.

---

## Requirements

| Component | Requirement |
|-----------|-------------|
| Linux kernel | 5.8+ (XDP native mode) |
| Privileges | `CAP_BPF` + `CAP_NET_ADMIN`, or root |
| Network driver | XDP native mode: Intel ixgbe/i40e, Mellanox mlx4/mlx5, virtio_net; generic XDP as fallback |
| Build dependencies | clang 14+, llvm, libbpf-dev, make |

---

## Installation

### From source (Linux only)

```bash
# Ubuntu/Debian
sudo apt-get install -y clang llvm libbpf-dev linux-headers-$(uname -r) make

git clone https://github.com/niksecops-crypto/ebpf-shield.git
cd ebpf-shield
make generate   # compiles bpf/shield.c → Go bindings
make build      # builds the shield binary
```

### Container (recommended for production)

```bash
docker pull ghcr.io/niksecops-crypto/ebpf-shield:latest

docker run --rm \
  --privileged \
  --network host \
  -v $(pwd)/config:/etc/shield:ro \
  ghcr.io/niksecops-crypto/ebpf-shield:latest \
  --config /etc/shield/shield.yaml
```

The container uses a Distroless runtime image — no shell, minimal attack surface.

---

## Configuration

Edit `config/shield.yaml`:

```yaml
interface: eth0   # interface to attach XDP program to

# blacklist: source IPs dropped for ALL ports, no response sent
blacklist:
  - 203.0.113.0/24       # known malicious /24
  - 198.51.100.42        # specific bad actor

# protected_ports: TCP ports hidden from all but listed trusted_ips
protected_ports:
  - port: 22
    trusted_ips:
      - 10.0.0.10        # bastion host
      - 10.0.0.11        # secondary bastion

  - port: 6379           # Redis
    trusted_ips:
      - 10.0.1.0/32      # app server 1 — note: only plain IPs here, not CIDRs
      - 10.0.1.1/32      # app server 2

  - port: 9090           # metrics endpoint
    trusted_ips:
      - 10.0.0.50        # Prometheus scraper
```

### Configuration validation

```bash
./shield --config config/shield.yaml --validate   # exit 0 = config is valid
```

---

## Running in Production

```bash
# Systemd service (installs via deploy.sh)
sudo ./scripts/deploy.sh

# Verify it's running
systemctl status ebpf-shield
journalctl -u ebpf-shield -f

# Graceful shutdown
systemctl stop ebpf-shield
```

### Systemd unit file

```ini
[Unit]
Description=eBPF-Shield XDP Firewall
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/shield --config /etc/ebpf-shield/shield.yaml
Restart=on-failure
RestartSec=5
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
```

---

## Commercial Use Cases

### 1. Port Hiding / Stealth Mode

Hide administrative ports (SSH, internal APIs) from the entire internet except a set of known management IPs:

```yaml
protected_ports:
  - port: 22
    trusted_ips: [10.0.0.10]   # only bastion host sees SSH
  - port: 8443
    trusted_ips: [10.0.0.10, 10.0.0.11]
```

From an attacker's perspective, these ports do not exist — they receive no response, not even a TCP RST.

### 2. Zero-Trust Database Access

Protect Redis, PostgreSQL, MongoDB ports so they are inaccessible from outside the application tier:

```yaml
protected_ports:
  - port: 5432   # PostgreSQL
    trusted_ips:
      - 10.1.0.0  # app-server-1
      - 10.1.0.1  # app-server-2
  - port: 6379   # Redis
    trusted_ips:
      - 10.1.0.0
      - 10.1.0.1
```

### 3. IP Reputation Blocking

Maintain a blocklist of known malicious IPs/ranges and reload without service interruption:

```bash
# Update blocklist and reload (no XDP detach/reattach needed)
sudo shield --config /etc/shield/shield.yaml --reload
```

---

## Performance

XDP processes packets at driver receive time, before any kernel networking stack involvement.

| Mode | Typical throughput | CPU per Mpps |
|------|-------------------|--------------|
| XDP native | 10–20 Mpps | <5% one core |
| XDP generic (fallback) | 1–3 Mpps | 15–25% one core |

Use `ethtool -i <iface>` to verify your driver supports XDP native mode.

---

## Kernel Compatibility

| Kernel version | Feature |
|---------------|---------|
| 4.8 | XDP introduced |
| 5.4 | BPF hash maps at XDP stable |
| 5.8+ | Full cilium/ebpf feature set, recommended |

Check your kernel: `uname -r`

---

## Troubleshooting

**`failed to attach XDP program: operation not supported`**
Your driver does not support XDP native mode. Either upgrade the driver or eBPF-Shield will fall back to generic XDP (lower throughput).

**`failed to remove RLIMIT_MEMLOCK`**
The process needs `CAP_SYS_RESOURCE` or root. Add `LimitMEMLOCK=infinity` to the systemd unit.

**Traffic still getting through after adding to blacklist**
Run `bpftool map dump name blacklist_map` to verify the IP was actually inserted into the BPF map.

**How to verify the XDP program is attached**
```bash
ip link show dev eth0
# Should show: xdpgeneric or xdp in the flags
bpftool net list dev eth0
```
