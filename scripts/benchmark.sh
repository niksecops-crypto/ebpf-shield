#!/bin/bash
# scripts/benchmark.sh
# Automation script for ebpf-shield throughput and latency benchmarking using nsente

set -euo pipefail

# Ensure script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

SENDER_NS="ns-sender"
RECEIVER_NS="ns-receiver"
VETH_SEND="veth-send"
VETH_RECV="veth-recv"
SENDER_IP="10.0.0.1"
RECEIVER_IP="10.0.0.2"
PORT=8080

PARENT_PID=$$

# Clean up any leftover namespaces
cleanup() {
    # Only run cleanup in the parent shell process
    if [ "${BASHPID:-$$}" -ne "$PARENT_PID" ]; then
        return
    fi
    echo "--- Cleaning up namespaces and processes ---"
    pkill -9 -f "iperf3" || true
    pkill -9 -f "http.server" || true
    killall -9 ebpf-shield 2>/dev/null || true
    ip netns del $SENDER_NS 2>/dev/null || true
    ip netns del $RECEIVER_NS 2>/dev/null || true
    rm -f benchmark_allowed.yaml benchmark_blocked.yaml
}

trap cleanup EXIT

# Run initial cleanup
echo "--- Initial cleanup ---"
pkill -9 -f "iperf3" || true
pkill -9 -f "http.server" || true
killall -9 ebpf-shield 2>/dev/null || true
ip netns del $SENDER_NS 2>/dev/null || true
ip netns del $RECEIVER_NS 2>/dev/null || true
sleep 2

echo "--- Setting up Virtual Network namespaces ---"
ip netns add $SENDER_NS
ip netns add $RECEIVER_NS

ip link add $VETH_SEND type veth peer name $VETH_RECV
ip link set $VETH_SEND netns $SENDER_NS
ip link set $VETH_RECV netns $RECEIVER_NS

# Configure sende
nsenter --net=/run/netns/$SENDER_NS ip addr add $SENDER_IP/24 dev $VETH_SEND
nsenter --net=/run/netns/$SENDER_NS ip link set dev $VETH_SEND up
nsenter --net=/run/netns/$SENDER_NS ip link set dev lo up

# Configure receive
nsenter --net=/run/netns/$RECEIVER_NS ip addr add $RECEIVER_IP/24 dev $VETH_RECV
nsenter --net=/run/netns/$RECEIVER_NS ip link set dev $VETH_RECV up
nsenter --net=/run/netns/$RECEIVER_NS ip link set dev lo up

echo "--- Starting Target Servers in Receiver Namespace ---"
# Start a lightweight Python HTTP server on port 8080
nsenter --net=/run/netns/$RECEIVER_NS python3 -m http.server $PORT > /dev/null 2>&1 &
# Start iperf3 serve
nsenter --net=/run/netns/$RECEIVER_NS iperf3 -s -D >/dev/null 2>&1

sleep 2

# ----------------- Scenario A: Baseline -----------------
echo -e "\n========================================= "
echo "  SCENARIO A: Baseline No Firewall        "
echo "========================================= "

echo "Measuring TCP Bandwidth..."
nsenter --net=/run/netns/$SENDER_NS iperf3 -c $RECEIVER_IP -t 5 || true

echo "Measuring UDP Bandwidth..."
nsenter --net=/run/netns/$SENDER_NS iperf3 -c $RECEIVER_IP -u -b 50M -t 5 || true

echo "Measuring HTTP Latency..."
nsenter --net=/run/netns/$SENDER_NS wrk -t2 -c50 -d5s --latency http://$RECEIVER_IP:$PORT/ || true


# ----------------- Scenario B: Allowed Traffic -----------------
echo -e "\n========================================= "
echo "  SCENARIO B: Allowed Traffic             "
echo "========================================= "

# Restart HTTP server to ensure it is fresh and responsive
pkill -9 -f "http.server" || true
sleep 1
nsenter --net=/run/netns/$RECEIVER_NS python3 -m http.server $PORT > /dev/null 2>&1 &
sleep 1

# Create config where sender IP is trusted on port 8080
cat <<EOF > benchmark_allowed.yaml
interface: $VETH_RECV
blacklist: []
protected_ports:
  - port: $PORT
    trusted_ips:
      - $SENDER_IP
EOF

# Start ebpf-shield in receiver namespace
echo "Starting ebpf-shield with ALLOWED config..."
rm -f /tmp/benchmark-daemon-B.log
nsenter --net=/run/netns/$RECEIVER_NS ./ebpf-shield -config benchmark_allowed.yaml > /tmp/benchmark-daemon-B.log 2>&1 &
SHIELD_PID=$!
sleep 2

# Check if daemon is running
if ! kill -0 $SHIELD_PID 2>/dev/null; then
    echo "ERROR: ebpf-shield daemon crashed on startup in B!"
    cat /tmp/benchmark-daemon-B.log
    exit 1
fi

echo "Measuring TCP Bandwidth..."
nsenter --net=/run/netns/$SENDER_NS iperf3 -c $RECEIVER_IP -t 5 || true

echo "Measuring UDP Bandwidth..."
nsenter --net=/run/netns/$SENDER_NS iperf3 -c $RECEIVER_IP -u -b 50M -t 5 || true

echo "Measuring HTTP Latency..."
nsenter --net=/run/netns/$SENDER_NS wrk -t2 -c50 -d5s --latency http://$RECEIVER_IP:$PORT/ || true

# Check if daemon is STILL running
if ! kill -0 $SHIELD_PID 2>/dev/null; then
    echo "ERROR: ebpf-shield daemon crashed during Scenario B benchmarks!"
    cat /tmp/benchmark-daemon-B.log
    exit 1
fi

# Clean up ebpf-shield instance
kill $SHIELD_PID || true
sleep 1


# ----------------- Scenario C: Blocked Traffic -----------------
echo -e "\n========================================= "
echo "  SCENARIO C: Blocked Traffic             "
echo "========================================= "

# Restart HTTP serve
pkill -9 -f "http.server" || true
sleep 1
nsenter --net=/run/netns/$RECEIVER_NS python3 -m http.server $PORT > /dev/null 2>&1 &
sleep 1

# Create config where sender IP is NOT trusted
cat <<EOF > benchmark_blocked.yaml
interface: $VETH_RECV
blacklist: []
protected_ports:
  - port: $PORT
    trusted_ips:
      - 10.0.0.99
EOF

echo "Starting ebpf-shield with BLOCKED config..."
rm -f /tmp/benchmark-daemon-C.log
nsenter --net=/run/netns/$RECEIVER_NS ./ebpf-shield -config benchmark_blocked.yaml > /tmp/benchmark-daemon-C.log 2>&1 &
SHIELD_PID=$!
sleep 2

# Check if daemon is running
if ! kill -0 $SHIELD_PID 2>/dev/null; then
    echo "ERROR: ebpf-shield daemon crashed on startup in C!"
    cat /tmp/benchmark-daemon-C.log
    exit 1
fi

echo "Verifying traffic drops..."
if nsenter --net=/run/netns/$SENDER_NS nc -zv -w 2 $RECEIVER_IP $PORT; then
    echo "ERROR: Connection succeeded! Firewall failed to block."
else
    echo "SUCCESS: Traffic was successfully blocked."
fi

echo -e "\n--- Benchmarking Completed ---"
