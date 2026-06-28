package config

import (
	"fmt"
	"net"
	"os"

	"gopkg.in/yaml.v3"
)

// ProtectedPort describes one TCP port that should only be accessible from
// specific source IPs. All other traffic to this port is silently dropped.
type ProtectedPort struct {
	Port       uint16   `yaml:"port"`
	TrustedIPs []string `yaml:"trusted_ips"`
}

// Config is the top-level configuration for ebpf-shield.
type Config struct {
	Interface      string          `yaml:"interface"`
	Blacklist      []string        `yaml:"blacklist"`
	ProtectedPorts []ProtectedPort `yaml:"protected_ports"`
}

// Load reads and validates a shield.yaml configuration file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface must be specified")
	}
	for _, entry := range c.Blacklist {
		if net.ParseIP(entry) == nil {
			if _, _, err := net.ParseCIDR(entry); err != nil {
				return fmt.Errorf("invalid blacklist entry %q: not a valid IP or CIDR", entry)
			}
		}
	}
	for _, pp := range c.ProtectedPorts {
		if pp.Port == 0 {
			return fmt.Errorf("protected_ports entry has zero port")
		}
		if len(pp.TrustedIPs) == 0 {
			return fmt.Errorf("protected_ports[%d]: trusted_ips must not be empty", pp.Port)
		}
		for _, ip := range pp.TrustedIPs {
			if net.ParseIP(ip) == nil {
				return fmt.Errorf("protected_ports[%d]: invalid trusted_ip %q", pp.Port, ip)
			}
		}
	}
	return nil
}

// BlacklistIPs expands CIDR ranges and returns individual IPv4 addresses.
func (c *Config) BlacklistIPs() ([]net.IP, error) {
	var ips []net.IP
	for _, entry := range c.Blacklist {
		if ip := net.ParseIP(entry); ip != nil {
			if v4 := ip.To4(); v4 != nil {
				ips = append(ips, v4)
			}
			continue
		}
		ip, cidr, err := net.ParseCIDR(entry)
		if err != nil {
			return nil, err
		}
		for ip = ip.Mask(cidr.Mask); cidr.Contains(ip); inc(ip) {
			if v4 := ip.To4(); v4 != nil {
				ips = append(ips, append(net.IP{}, v4...))
			}
		}
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] != 0 {
			break
		}
	}
}
