package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/link"
	"github.com/niksecops-crypto/ebpf-shield/pkg/bpf"
	"github.com/niksecops-crypto/ebpf-shield/pkg/config"
)

var version = "dev"

// portIPKey mirrors struct port_ip_key in bpf/shield.c.
// Memory layout must match exactly: dst_port (u16), pad (u16), src_ip (u32).
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

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("failed to load config", "path", *configPath, "error", err)
		os.Exit(1)
	}

	slog.Info("ebpf-shield starting",
		"version", version,
		"interface", cfg.Interface,
		"blacklist_entries", len(cfg.Blacklist),
		"protected_ports", len(cfg.ProtectedPorts),
	)

	if err := syscall.Setrlimit(syscall.RLIMIT_MEMLOCK, &syscall.Rlimit{
		Cur: syscall.RLIM_INFINITY,
		Max: syscall.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to remove RLIMIT_MEMLOCK: %v", err)
	}

	objs := bpf.ShieldObjects{}
	if err := bpf.LoadShieldObjects(&objs, nil); err != nil {
		slog.Error("failed to load BPF objects", "error", err)
		os.Exit(1)
	}
	defer objs.Close()

	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		slog.Error("interface not found", "interface", cfg.Interface, "error", err)
		os.Exit(1)
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpShieldFunc,
		Interface: iface.Index,
	})
	if err != nil {
		slog.Error("failed to attach XDP program", "interface", cfg.Interface, "error", err)
		os.Exit(1)
	}
	defer l.Close()

	slog.Info("XDP program attached", "interface", cfg.Interface)

	// Populate blacklist_map
	blockedIPs, err := cfg.BlacklistIPs()
	if err != nil {
		slog.Error("failed to expand blacklist CIDRs", "error", err)
		os.Exit(1)
	}
	mark := uint8(1)
	for _, ip := range blockedIPs {
		key := binary.BigEndian.Uint32(ip)
		if err := objs.BlacklistMap.Put(&key, &mark); err != nil {
			slog.Warn("blacklist insert failed", "ip", ip.String(), "error", err)
		} else {
			slog.Info("blacklisted", "ip", ip.String())
		}
	}

	// Populate protected_ports_map and port_acl_map
	for _, pp := range cfg.ProtectedPorts {
		portNBO := htons(pp.Port)
		if err := objs.ProtectedPortsMap.Put(&portNBO, &mark); err != nil {
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
				SrcIP:   binary.BigEndian.Uint32(ip),
			}
			if err := objs.PortAclMap.Put(&key, &mark); err != nil {
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
