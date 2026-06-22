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
		slog.Error("failed to attach XDP", "interface", cfg.Interface, "error", err)
		os.Exit(1)
	}
	defer l.Close()

	slog.Info("ebpf-shield attached", "interface", cfg.Interface, "version", version)

	blockedIPs, err := cfg.BlacklistIPs()
	if err != nil {
		slog.Error("failed to expand blacklist", "error", err)
		os.Exit(1)
	}

	for _, ip := range blockedIPs {
		key := binary.LittleEndian.Uint32(ip)
		if err := objs.BlacklistMap.Put(&key, &key); err != nil {
			slog.Warn("failed to insert blacklist IP", "ip", ip.String(), "error", err)
		} else {
			slog.Info("blacklisted", "ip", ip.String())
		}
	}

	for i, pp := range cfg.ProtectedPorts {
		trustedIP := net.ParseIP(pp.TrustedIP).To4()
		if trustedIP == nil {
			slog.Warn("skipping invalid trusted IP", "entry", i)
			continue
		}
		ipUint32 := binary.LittleEndian.Uint32(trustedIP)
		idx := uint32(i)
		if err := objs.SettingsMap.Put(&idx, &ipUint32); err != nil {
			slog.Warn("failed to set trusted IP", "port", pp.Port, "error", err)
		} else {
			slog.Info("protected port configured", "port", pp.Port, "trusted_ip", pp.TrustedIP)
		}
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	slog.Info("ebpf-shield shutting down")
}
