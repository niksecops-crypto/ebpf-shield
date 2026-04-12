package main

import (
	"encoding/binary"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/niksecops-crypto/ebpf-shield/pkg/bpf"
)

func main() {
	// Remove RLIMIT_MEMLOCK (required for older kernels)
	if err := syscall.Setrlimit(syscall.RLIMIT_MEMLOCK, &syscall.Rlimit{
		Cur: syscall.RLIM_INFINITY,
		Max: syscall.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("Failed to remove RLIMIT_MEMLOCK: %v", err)
	}

	// Load BPF programs and maps
	objs := bpf.ShieldObjects{}
	if err := bpf.LoadShieldObjects(&objs, nil); err != nil {
		log.Fatalf("Failed to load BPF objects: %v", err)
	}
	defer objs.Close()

	// Find the network interface
	ifaceName := "eth0" // Default to eth0
	if len(os.Args) > 1 {
		ifaceName = os.Args[1]
	}
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Fatalf("Failed to get interface %s: %v", ifaceName, err)
	}

	// Attach XDP program to the interface
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpShieldFunc,
		Interface: iface.Index,
	})
	if err != nil {
		log.Fatalf("Failed to attach XDP program: %v", err)
	}
	defer l.Close()

	log.Printf("Ebpf-Shield attached to interface %s", ifaceName)
	log.Printf("Filtering and obfuscating traffic...")

	// Block a specific IP as an example (e.g. 1.2.3.4)
	ipToBlock := net.ParseIP("1.2.3.4").To4()
	if ipToBlock != nil {
		ipUint32 := binary.LittleEndian.Uint32(ipToBlock)
		
		err := objs.BlacklistMap.Put(&ipUint32, &ipUint32)
		if err != nil {
			log.Printf("Warning: Failed to block IP %s: %v", ipToBlock, err)
		} else {
			log.Printf("Blacklisted IP: %s", ipToBlock)
		}
	}

	// Set trusted IP to allow proxy access (e.g. 192.168.1.1)
	trustedIP := net.ParseIP("192.168.1.1").To4()
	if trustedIP != nil {
		ipUint32 := binary.LittleEndian.Uint32(trustedIP)
		
		index := uint32(0)
		err := objs.SettingsMap.Put(&index, &ipUint32)
		if err != nil {
			log.Printf("Warning: Failed to set trusted IP: %v", err)
		} else {
			log.Printf("Trusted IP for proxy (8080): %s", trustedIP)
		}
	}

	// Wait for termination signal
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig

	log.Println("Ebpf-Shield shutting down...")
}
