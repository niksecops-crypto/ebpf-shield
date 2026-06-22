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
    trusted_ip: 10.0.0.1
`

const missingInterface = `
blacklist:
  - 192.0.2.1
`

const badIP = `
interface: eth0
blacklist:
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
	if len(cfg.ProtectedPorts) != 1 {
		t.Errorf("expected 1 protected port, got %d", len(cfg.ProtectedPorts))
	}
}

func TestLoad_MissingInterface(t *testing.T) {
	_, err := Load(writeTmp(t, missingInterface))
	if err == nil {
		t.Error("expected error for missing interface")
	}
}

func TestLoad_InvalidIP(t *testing.T) {
	_, err := Load(writeTmp(t, badIP))
	if err == nil {
		t.Error("expected error for invalid IP")
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

	// 10.0.0.0/30 gives 4 IPs (.0, .1, .2, .3) + 1 plain IP
	if len(ips) < 5 {
		t.Errorf("expected at least 5 IPs after CIDR expansion, got %d", len(ips))
	}
}
