package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// ShieldHandles holds loaded BPF objects for the XDP shield program.
// Callers are responsible for calling Close when done.
type ShieldHandles struct {
	XdpShieldFunc     *ebpf.Program
	BlacklistMap      *ebpf.Map
	ProtectedPortsMap *ebpf.Map
	PortAclMap        *ebpf.Map
}

// Close releases all BPF resources.
func (h *ShieldHandles) Close() {
	if h.XdpShieldFunc != nil {
		h.XdpShieldFunc.Close()
	}
	if h.BlacklistMap != nil {
		h.BlacklistMap.Close()
	}
	if h.ProtectedPortsMap != nil {
		h.ProtectedPortsMap.Close()
	}
	if h.PortAclMap != nil {
		h.PortAclMap.Close()
	}
}

// LoadShield loads the compiled XDP program and BPF maps into the kernel
// and returns handles to interact with them.
func LoadShield() (*ShieldHandles, error) {
	var objs shieldObjects
	if err := loadShieldObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("load shield BPF objects: %w", err)
	}

	return &ShieldHandles{
		XdpShieldFunc:     objs.XdpShieldFunc,
		BlacklistMap:      objs.BlacklistMap,
		ProtectedPortsMap: objs.ProtectedPortsMap,
		PortAclMap:        objs.PortAclMap,
	}, nil
}
