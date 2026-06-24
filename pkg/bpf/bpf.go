package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpf -type port_ip_key shield ../../bpf/shield.c -- -I../../headers
