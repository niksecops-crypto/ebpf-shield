package bpf

import (
	"encoding/binary"
	"net"
	"testing"
)

func TestIPConversion(t *testing.T) {
	ip := net.ParseIP("1.2.3.4").To4()
	if ip == nil {
		t.Fatal("Failed to parse IP")
	}

	// XDP uses little-endian or big-endian depending on the architecture
	// But in our Go code, we should match what the BPF program expects
	// (usually host byte order for values in maps, or network byte order for packet data)
	
	val := binary.LittleEndian.Uint32(ip)
	expected := uint32(1) | uint32(2)<<8 | uint32(3)<<16 | uint32(4)<<24
	
	if val != expected {
		t.Errorf("Expected %d, got %d", expected, val)
	}
}
