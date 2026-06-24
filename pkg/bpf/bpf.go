package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go shield ../../bpf/shield.c -- -I../../headers
