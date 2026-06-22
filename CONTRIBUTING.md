# Contributing to ebpf-shield

## Requirements

- Linux kernel 5.8+ (XDP support)
- Go 1.22+
- clang + llvm (for BPF compilation)
- `CAP_BPF` or root for integration tests

```bash
# Ubuntu/Debian
sudo apt-get install clang llvm libbpf-dev linux-headers-$(uname -r)
```

## Getting Started

```bash
git clone https://github.com/niksecops-crypto/ebpf-shield.git
cd ebpf-shield
make generate   # compile BPF C → Go bindings
make build
make test       # unit tests (no root needed)
```

## Development Workflow

1. Fork and branch: `git checkout -b feat/my-feature`
2. BPF changes go in `bpf/shield.c` → run `make generate` after
3. Go userspace changes go in `cmd/shield/` and `pkg/`
4. Config changes go in `pkg/config/` with tests in `pkg/config/config_test.go`
5. `make test && make lint` before PR

## Testing Without a Real Interface

Unit tests in `pkg/config/` require no kernel. Integration tests that load BPF programs need a Linux environment with `CAP_BPF`.

## Reporting Issues

Open a [GitHub Issue](https://github.com/niksecops-crypto/ebpf-shield/issues) with:
- Kernel version (`uname -r`)
- Network interface driver
- Error output from `shield --config ...`
