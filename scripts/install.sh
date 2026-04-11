#!/bin/bash
set -e

echo "--- Installing dependencies ---"
sudo apt-get update
sudo apt-get install -y clang llvm linux-libc-dev libbpf-dev make git golang-go

echo "--- Building Ebpf-Shield ---"
make all

echo "--- Installation complete ---"
echo "You can now run: sudo ./ebpf-shield <interface>"
