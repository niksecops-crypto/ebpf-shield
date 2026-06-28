package bpf

import (
	"encoding/binary"
	"net"
	"testing"
	"testing/quick"
)

// Helper to construct a mock Ethernet/IP/TCP frame
func craftTCPPacket(srcIP net.IP, dstIP net.IP, dstPort uint16) []byte {
	// Simplified packet construction (14-byte Eth, 20-byte IP, 20-byte TCP)
	buf := make([]byte, 14+20+20)

	// Ethernet Header (IPv4 type = 0x0800)
	binary.BigEndian.PutUint16(buf[12:14], 0x0800)

	// IP Header (protocol TCP = 6, length = 40)
	buf[14] = 0x45 // Version & IHL
	buf[23] = 6    // Protocol
	copy(buf[26:30], srcIP.To4())
	copy(buf[30:34], dstIP.To4())

	// TCP Header (dest port)
	binary.BigEndian.PutUint16(buf[36:38], dstPort)
	return buf
}

func TestXDP_Properties(t *testing.T) {
	// 1. Load BPF program
	handles, err := LoadShield()
	if err != nil {
		t.Skip("Skipping BPF test: requires root / CAP_BPF")
	}
	defer handles.Close()

	// 2. Define Properties to assert
	assertion := func(srcInt uint32, dstPort uint16, isBlacklisted bool, isProtected bool, isAllowed bool) bool {
		srcIP := make(net.IP, 4)
		binary.BigEndian.PutUint32(srcIP, srcInt)
		dstIP := net.ParseIP("10.0.0.2")

		// Calculate host byte-order value loaded by BPF program
		srcIPVal := binary.LittleEndian.Uint32(srcIP)

		// Configure maps for this iteration
		mark := uint8(1)
		if isBlacklisted {
			handles.BlacklistMap.Put(&srcIPVal, &mark)
			defer handles.BlacklistMap.Delete(&srcIPVal)
		}

		portNBO := htons(dstPort)
		if isProtected {
			handles.ProtectedPortsMap.Put(&portNBO, &mark)
			defer handles.ProtectedPortsMap.Delete(&portNBO)
		}

		if isAllowed {
			key := portIPKey{DstPort: portNBO, Pad: 0, SrcIP: srcIPVal}
			handles.PortAclMap.Put(&key, &mark)
			defer handles.PortAclMap.Delete(&key)
		}

		// Craft packet and run in kernel
		packet := craftTCPPacket(srcIP, dstIP, dstPort)
		ret, _, err := handles.XdpShieldFunc.Test(packet)
		if err != nil {
			t.Fatalf("BPF_PROG_TEST_RUN failed: %v", err)
		}

		// ASSERTIONS
		// Property 1: Blacklisted IP always dropped (XDP_DROP = 1)
		if isBlacklisted {
			return ret == 1
		}
		// Property 2: Port protected and IP not allowed -> XDP_DROP
		if isProtected && !isAllowed {
			return ret == 1
		}
		// Property 3: Port protected and IP allowed -> XDP_PASS = 2
		if isProtected && isAllowed {
			return ret == 2
		}
		// Property 4: Unprotected port -> XDP_PASS
		return ret == 2
	}

	if err := quick.Check(assertion, &quick.Config{MaxCount: 100}); err != nil {
		t.Error(err)
	}
}

type portIPKey struct {
	DstPort uint16
	Pad     uint16
	SrcIP   uint32
}

func htons(v uint16) uint16 {
	return (v<<8)&0xff00 | v>>8
}
