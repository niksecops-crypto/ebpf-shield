#!/bin/bash
# Deployment script for Ebpf-Shield
# Runs on the target Linux server

# 1. Install dependencies and build
./scripts/install.sh

# 2. Install binary to system path
make install

# 3. Setup systemd service
sudo cp deploy/ebpf-shield.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ebpf-shield

echo "Deployment complete! Check status with: systemctl status ebpf-shield"
