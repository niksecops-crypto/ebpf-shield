# Changelog

## [1.1.0] - 2024-12-10
### Added
- YAML configuration file support (`config/shield.yaml`)
- `pkg/config` package with validation and CIDR expansion
- Unit tests for config loading and IP expansion
- `--config` CLI flag to specify config path at runtime
- GitHub Actions CI workflow

### Changed
- Removed hardcoded IPs from `main.go`; all rules now come from config file
- Interface name configurable via YAML (was argv[1])

## [1.0.0] - 2024-10-25
### Added
- Initial release: XDP-based packet filtering using cilium/ebpf
- IP blacklist via eBPF hash map
- Stealth port protection (no ICMP/TCP response on drop)
- Systemd service unit
- Install/deploy scripts
