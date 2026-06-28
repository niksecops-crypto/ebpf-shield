package bpf

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func runChaosCmd(t *testing.T, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		return "", fmt.Errorf("cmd %s %v failed: %w, stderr: %s", name, args, err, stderr.String())
	}
	return stdout.String(), nil
}

func setupChaosNamespaces(t *testing.T) {
	t.Helper()
	// Del if exists
	exec.Command("ip", "netns", "del", "ns-chaos-client").Run()
	exec.Command("ip", "netns", "del", "ns-chaos-shield").Run()

	if _, err := runChaosCmd(t, "ip", "netns", "add", "ns-chaos-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "netns", "add", "ns-chaos-shield"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "link", "add", "veth-cclient", "type", "veth", "peer", "name", "veth-cshield"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "link", "set", "veth-cclient", "netns", "ns-chaos-client"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "link", "set", "veth-cshield", "netns", "ns-chaos-shield"); err != nil {
		t.Fatal(err)
	}

	// IPs
	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-client", "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-client", "ip", "addr", "add", "10.99.9.2/24", "dev", "veth-cclient"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-client", "ip", "addr", "add", "10.99.9.3/24", "dev", "veth-cclient"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-client", "ip", "link", "set", "veth-cclient", "up"); err != nil {
		t.Fatal(err)
	}

	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-shield", "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-shield", "ip", "addr", "add", "10.99.9.1/24", "dev", "veth-cshield"); err != nil {
		t.Fatal(err)
	}
	if _, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-shield", "ip", "link", "set", "veth-cshield", "up"); err != nil {
		t.Fatal(err)
	}
}

func checkChaosTCP(t *testing.T, srcIP string, expectPass bool) {
	t.Helper()
	_, err := runChaosCmd(t, "ip", "netns", "exec", "ns-chaos-client", "nc", "-s", srcIP, "-zv", "-w", "1", "10.99.9.1", "8080")
	if expectPass {
		if err != nil {
			t.Errorf("TCP connection from %s expected to PASS, but FAILED: %v", srcIP, err)
		}
	} else {
		if err == nil {
			t.Errorf("TCP connection from %s expected to DROP, but PASSED", srcIP)
		}
	}
}

func TestChaos_ControllerCrash(t *testing.T) {
	// Skip if not running in WSL / Linux as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping chaos integration test: requires root privileges")
	}

	tmpDir := t.TempDir()
	binPath := filepath.Join(tmpDir, "ebpf-shield")

	// Compile ebpf-shield
	t.Log("Building ebpf-shield executable for chaos test...")
	cmdBuild := exec.Command("go", "build", "-buildvcs=false", "-o", binPath, "../../cmd/shield")
	if out, err := cmdBuild.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build ebpf-shield: %v, output: %s", err, string(out))
	}

	setupChaosNamespaces(t)
	defer func() {
		exec.Command("ip", "netns", "del", "ns-chaos-client").Run()
		exec.Command("ip", "netns", "del", "ns-chaos-shield").Run()
		os.Remove("/sys/fs/bpf/ebpf-shield-link")
	}()

	// Start a TCP server inside ns-chaos-shield on port 8080
	tcpServer := exec.Command("ip", "netns", "exec", "ns-chaos-shield", "nc", "-lk", "10.99.9.1", "8080")
	if err := tcpServer.Start(); err != nil {
		t.Fatalf("Failed to start TCP server in namespace: %v", err)
	}
	defer tcpServer.Process.Kill()
	time.Sleep(200 * time.Millisecond)

	// Write config
	configContent := `
interface: veth-cshield
protected_ports:
  - port: 8080
    trusted_ips:
      - 10.99.9.2
`
	configPath := filepath.Join(tmpDir, "shield-chaos.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatal(err)
	}

	// Start the daemon using nsenter to ensure link pinning shares the host's /sys/fs/bpf
	logFile, err := os.OpenFile("/tmp/chaos_daemon.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	daemonCmd := exec.Command("nsenter", "--net=/run/netns/ns-chaos-shield", binPath, "-config", configPath)
	daemonCmd.Stdout = logFile
	daemonCmd.Stderr = logFile

	if err := daemonCmd.Start(); err != nil {
		t.Fatalf("Failed to start daemon: %v", err)
	}

	// Wait for XDP to attach and pin
	time.Sleep(1500 * time.Millisecond)

	defer func() {
		if t.Failed() {
			logData, _ := os.ReadFile("/tmp/chaos_daemon.log")
			t.Logf("Daemon Output:\n%s", string(logData))
		}
	}()

	// 1. Verify protection is active
	checkChaosTCP(t, "10.99.9.2", true)  // Trusted -> Pass
	checkChaosTCP(t, "10.99.9.3", false) // Untrusted -> Drop

	// 2. Kill the daemon with SIGKILL (prevents graceful cleanup/unpinning)
	t.Log("Simulating crash: sending SIGKILL to daemon...")
	if err := daemonCmd.Process.Signal(syscall.SIGKILL); err != nil {
		t.Fatalf("Failed to SIGKILL daemon: %v", err)
	}
	_ = daemonCmd.Wait()

	// 3. Assert: XDP program link is still pinned to bpffs
	const pinPath = "/sys/fs/bpf/ebpf-shield-link"
	if _, err := os.Stat(pinPath); os.IsNotExist(err) {
		t.Error("FAIL: XDP link unpinned after crash!")
	}

	// 4. Assert: Filtering remains functional even though daemon is dead
	t.Log("Verifying filtering still functions post-crash...")
	checkChaosTCP(t, "10.99.9.2", true)  // Trusted -> Pass (BPF map keeps allowlist)
	checkChaosTCP(t, "10.99.9.3", false) // Untrusted -> Drop
}
