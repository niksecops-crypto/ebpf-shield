# Ebpf-Shield: Advanced Network Obfuscator & Shield

Ebpf-Shield is a low-level network security tool leveraging eBPF/XDP for kernel-level packet filtering and traffic obfuscation. It allows for high-performance drop/pass logic before the packet even reaches the standard Linux networking stack.

## Overview

Traditional firewalls (iptables/nftables) operate later in the packet processing cycle. Ebpf-Shield uses XDP (eXpress Data Path) to intercept traffic at the driver level, providing:
- Minimum CPU overhead per packet.
- Protection against port scanning by silently dropping unauthorized traffic ("stealth mode").
- Dynamic IP blacklisting via eBPF Hash Maps.
- Zero-Trust port protection for critical services (e.g., hiding port 8080).

## Architecture

- **Kernel Space**: C-based XDP program ([shield.c](bpf/shield.c)) inspecting Ethernet frames.
- **User Space**: Go-based controller ([main.go](cmd/shield/main.go)) managing BPF objects and map updates.

### How it works
1. Incoming packet is parsed by the XDP hook.
2. Source IP is looked up in the `blacklist_map`. If present, `XDP_DROP`.
3. If destination port is protected (e.g., 8080), the source IP is verified against `settings_map`. Non-matching packets are dropped without ICMP/TCP response.
4. Authorized traffic proceeds via `XDP_PASS`.

---

## Ebpf-Shield: Сетевой обфускатор на базе eBPF

Ebpf-Shield — это инструмент для обеспечения сетевой безопасности, использующий eBPF/XDP для фильтрации трафика на уровне ядра. Позволяет реализовать логику обработки пакетов до их попадания в стандартный сетевой стек Linux.

## Основные возможности

- **Минимальные задержки**: Обработка на уровне драйвера (XDP).
- **Обфускация сервисов**: Скрытие портов от сканеров (пакеты отбрасываются без ответа).
- **Динамические списки**: Управление блокировками через BPF Maps без перезапуска правил.
- **Zero-Trust**: Доступ к защищенным портам только для доверенных IP.

## Использование (Usage)

### Build & Install
```bash
# Ubuntu/Debian dependencies
sudo apt-get update && sudo apt-get install -y clang llvm linux-libc-dev libbpf-dev make

# Build everything
make all

# Full deployment (including systemd service)
sudo ./scripts/deploy.sh
```

### Run
```bash
sudo ./ebpf-shield eth0
```

---

## Development

The project uses `cilium/ebpf` for Go bindings. 
To regenerate BPF objects:
```bash
make generate
```

## Production Notes
- Requires `CAP_BPF` or `root`.
- Best performance achieved with Native XDP supported drivers.
- Monitoring via `journalctl -u ebpf-shield -f`.

---
*By [niksecops-crypto](https://github.com/niksecops-crypto)*
