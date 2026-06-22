package config

import (
	"os"
	"testing"
)

const validConfig = `
interface: eth0
blacklist:
  - 192.0.2.1
  - 10.0.0.0/30
protected_ports:
  - port: 8080
    trusted_ips:
      - 10.0.0.1
      - 10.0.0.2
  - port: 9090
    trusted_ips:
      - 10.0.0.1
`

const missingInterface = `
blacklist:
  - 192.0.2.1
`

const badBlacklistIP = `
interface: eth0
blacklist:
  - not-an-ip
`

const emptyTrustedIPs = `
interface: eth0
protected_ports:
  - port: 8080
    trusted_ips: []
`

const invalidTrustedIP = `
interface: eth0
protected_ports:
  - port: 8080
    trusted_ips:
      - not-an-ip
`

func writeTmp(t *testing.T, content string) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "shield-*.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(content); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return f.Name()
}

func TestLoad_ValidConfig(t *testing.T) {
	cfg, err := Load(writeTmp(t, validConfig))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Interface != "eth0" {
		t.Errorf("expected interface eth0, got %q", cfg.Interface)
	}
	if len(cfg.Blacklist) != 2 {
		t.Errorf("expected 2 blacklist entries, got %d", len(cfg.Blacklist))
	}
	if len(cfg.ProtectedPorts) != 2 {
		t.Errorf("expected 2 protected ports, got %d", len(cfg.ProtectedPorts))
	}
	if len(cfg.ProtectedPorts[0].TrustedIPs) != 2 {
		t.Errorf("expected 2 trusted IPs for port 8080, got %d", len(cfg.ProtectedPorts[0].TrustedIPs))
	}
}

func TestLoad_MissingInterface(t *testing.T) {
	_, err := Load(writeTmp(t, missingInterface))
	if err == nil {
		t.Error("expected error for missing interface")
	}
}

func TestLoad_InvalidBlacklistIP(t *testing.T) {
	_, err := Load(writeTmp(t, badBlacklistIP))
	if err == nil {
		t.Error("expected error for invalid blacklist IP")
	}
}

func TestLoad_EmptyTrustedIPs(t *testing.T) {
	_, err := Load(writeTmp(t, emptyTrustedIPs))
	if err == nil {
		t.Error("expected error for empty trusted_ips list")
	}
}

func TestLoad_InvalidTrustedIP(t *testing.T) {
	_, err := Load(writeTmp(t, invalidTrustedIP))
	if err == nil {
		t.Error("expected error for invalid trusted_ip")
	}
}

func TestLoad_FileNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/shield.yaml")
	if err == nil {
		t.Error("expected error for missing file")
	}
}

func TestBlacklistIPs_CIDRExpansion(t *testing.T) {
	cfg, err := Load(writeTmp(t, validConfig))
	if err != nil {
		t.Fatal(err)
	}

	ips, err := cfg.BlacklistIPs()
	if err != nil {
		t.Fatal(err)
	}

	// 10.0.0.0/30 gives 4 IPs (.0, .1, .2, .3) + 1 plain IP (192.0.2.1)
	if len(ips) < 5 {
		t.Errorf("expected at least 5 IPs after CIDR expansion, got %d", len(ips))
	}
}
