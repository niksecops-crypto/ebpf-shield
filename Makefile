BINARY_NAME=ebpf-shield
BPF_DIR=bpf
PKG_BPF_DIR=pkg/bpf

all: generate build

generate:
	@echo "Generating BPF objects..."
	cd $(PKG_BPF_DIR) && go generate

build:
	@echo "Building Go binary..."
	go build -o $(BINARY_NAME) ./cmd/shield/

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f $(PKG_BPF_DIR)/shield_bpfel.go $(PKG_BPF_DIR)/shield_bpfeb.go
	rm -f $(PKG_BPF_DIR)/shield_bpfel.o $(PKG_BPF_DIR)/shield_bpfeb.o

install-deps:
	@echo "Installing dependencies (Linux only)..."
	sudo apt-get update && sudo apt-get install -y llvm clang linux-libc-dev libbpf-dev

test:
	go test ./...

install: build
	@echo "Installing binary to /usr/local/bin..."
	sudo cp $(BINARY_NAME) /usr/local/bin/

.PHONY: all generate build clean install-deps test install
