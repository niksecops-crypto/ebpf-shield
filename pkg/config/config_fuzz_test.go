package config

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func FuzzLoadConfig(f *testing.F) {
	// Seed corpus with valid and invalid config variations
	f.Add([]byte("interface: eth0\nblacklist:\n  - 192.0.2.1"))
	f.Add([]byte("interface: eth0\nprotected_ports:\n  - port: 80\n    trusted_ips:\n      - 10.0.0.1"))
	f.Add([]byte("invalid_yaml: [["))

	f.Fuzz(func(t *testing.T, data []byte) {
		var cfg Config
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			return // Skip syntactically invalid YAML
		}

		// If YAML unmarshals, ensure our code handles expansion and validation safely
		_ = cfg.Validate()
		_, _ = cfg.BlacklistIPs()
	})
}
