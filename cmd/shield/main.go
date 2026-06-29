package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/niksecops-crypto/ebpf-shield/pkg/bpf"
	"github.com/niksecops-crypto/ebpf-shield/pkg/config"
	"gopkg.in/yaml.v3"
)

var version = "dev"

// portIPKey mirrors struct port_ip_key in bpf/shield.c.
// Layout: dst_port (u16) + pad (u16) + src_ip (u32) = 8 bytes.
type portIPKey struct {
	DstPort uint16
	Pad     uint16
	SrcIP   uint32
}

func main() {
	configPath := flag.String("config", "config/shield.yaml", "Path to shield.yaml")
	showVer := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVer {
		fmt.Println(version)
		os.Exit(0)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// Determine if config flag was explicitly set
	isConfigSet := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == "config" {
			isConfigSet = true
		}
	})

	var cfg config.Config
	actualConfigPath := *configPath
	configExists := true

	if _, err := os.Stat(actualConfigPath); os.IsNotExist(err) {
		configExists = false
		if !isConfigSet {
			// Fallback: check /etc/ebpf-shield/shield.yaml
			fallbackPath := "/etc/ebpf-shield/shield.yaml"
			if _, errF := os.Stat(fallbackPath); errF == nil {
				actualConfigPath = fallbackPath
				configExists = true
			}
		}
	}

	if configExists {
		data, err := os.ReadFile(actualConfigPath)
		if err != nil {
			slog.Error("failed to read config", "path", actualConfigPath, "error", err)
			os.Exit(1)
		}
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			slog.Error("failed to parse config", "path", actualConfigPath, "error", err)
			os.Exit(1)
		}
	} else {
		if isConfigSet {
			slog.Error("config file not found", "path", actualConfigPath)
			os.Exit(1)
		}
		slog.Info("no config file loaded, proceeding with defaults", "path", actualConfigPath)
	}

	// Overwrite interface if positional arg is provided and interface not specified in config
	if cfg.Interface == "" && flag.NArg() > 0 {
		cfg.Interface = flag.Arg(0)
	}

	// Validate config
	if err := cfg.Validate(); err != nil {
		slog.Error("invalid configuration", "error", err)
		os.Exit(1)
	}

	slog.Info("ebpf-shield starting",
		"version", version,
		"interface", cfg.Interface,
		"blacklist_entries", len(cfg.Blacklist),
		"protected_ports", len(cfg.ProtectedPorts),
	)

	// Required for kernels < 5.11; no-op on modern kernels with CAP_BPF.
	if err := rlimit.RemoveMemlock(); err != nil {
		slog.Error("failed to remove RLIMIT_MEMLOCK", "error", err)
		os.Exit(1)
	}

	handles, err := bpf.LoadShield()
	if err != nil {
		slog.Error("failed to load BPF objects", "error", err)
		os.Exit(1)
	}
	defer handles.Close()

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		slog.Error("interface not found", "interface", cfg.Interface, "error", err)
		os.Exit(1)
	}

	// Ensure bpffs is mounted on /sys/fs/bpf
	if err := os.MkdirAll("/sys/fs/bpf", 0750); err != nil {
		slog.Warn("failed to create /sys/fs/bpf", "error", err)
	}
	if err := syscall.Mount("bpf", "/sys/fs/bpf", "bpf", 0, ""); err != nil && err != syscall.EBUSY {
		slog.Warn("failed to mount bpffs on /sys/fs/bpf", "error", err)
	}

	const pinPath = "/sys/fs/bpf/ebpf-shield-link"
	if _, err := os.Stat(pinPath); err == nil {
		slog.Info("stale pin found, removing", "path", pinPath)
		os.Remove(pinPath)
	}

	// Detach any existing XDP program on the interface to avoid "device or resource busy"
	// if the daemon was killed ungracefully.
	_ = exec.Command("ip", "link", "set", "dev", cfg.Interface, "xdp", "off").Run()

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   handles.XdpShieldFunc,
		Interface: iface.Index,
	})
	if err != nil {
		slog.Error("failed to attach XDP program", "interface", cfg.Interface, "error", err)
		os.Exit(1)
	}
	defer l.Close()

	if err := l.Pin(pinPath); err != nil {
		slog.Error("failed to pin XDP link", "path", pinPath, "error", err)
		os.Exit(1)
	}
	defer os.Remove(pinPath)

	slog.Info("XDP program attached and pinned", "interface", cfg.Interface, "path", pinPath)

	// Populate blacklist_map
	blockedIPs, err := cfg.BlacklistIPs()
	if err != nil {
		slog.Error("failed to expand blacklist CIDRs", "error", err)
		os.Exit(1)
	}
	mark := uint8(1)
	for _, ip := range blockedIPs {
		key := binary.LittleEndian.Uint32(ip)
		if err := handles.BlacklistMap.Put(&key, &mark); err != nil {
			slog.Warn("blacklist insert failed", "ip", ip.String(), "error", err)
		} else {
			slog.Info("blacklisted", "ip", ip.String())
		}
	}

	// Populate protected_ports_map and port_acl_map
	for _, pp := range cfg.ProtectedPorts {
		portNBO := htons(pp.Port)
		if err := handles.ProtectedPortsMap.Put(&portNBO, &mark); err != nil {
			slog.Warn("failed to register protected port", "port", pp.Port, "error", err)
			continue
		}
		slog.Info("port protected", "port", pp.Port, "trusted_ips", len(pp.TrustedIPs))

		for _, ipStr := range pp.TrustedIPs {
			ip := net.ParseIP(ipStr).To4()
			if ip == nil {
				slog.Warn("skipping invalid trusted IP", "ip", ipStr)
				continue
			}
			key := portIPKey{
				DstPort: portNBO,
				Pad:     0,
				SrcIP:   binary.LittleEndian.Uint32(ip),
			}
			if err := handles.PortAclMap.Put(&key, &mark); err != nil {
				slog.Warn("ACL insert failed", "port", pp.Port, "ip", ipStr, "error", err)
			} else {
				slog.Info("ACL entry added", "port", pp.Port, "trusted_ip", ipStr)
			}
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("ebpf-shield shutting down")
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
