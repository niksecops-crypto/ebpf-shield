package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type xdp_shield_func shield ../../bpf/shield.c -- -I../../headers
