//go:build !js

package client_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestWasmEndToEnd builds the client's js/wasm test binary and runs it under
// node against a real server started here: the browser transport (the browser's
// WebSocket, through syscall/js) speaks to the same grpc.Server as the native one.
func TestWasmEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("-short")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed")
	}
	base := server(t, nil)
	goroot := runtime.GOROOT()
	bin := filepath.Join(t.TempDir(), "client.test.wasm")
	build := exec.Command("go", "test", "-c", "-o", bin, "github.com/go-turn/turn/rendezvous/client")
	build.Env = append(os.Environ(), "GOOS=js", "GOARCH=wasm")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the wasm test: %v\n%s", err, out)
	}
	run := exec.Command(node, filepath.Join(goroot, "lib", "wasm", "wasm_exec_node.js"), bin, "-test.v", "-test.run", "^TestWasmRoundTrip$")
	// A small environment: wasm_exec refuses a total of more than 8 KiB of command
	// line and environment, which a Windows runner's environment exceeds.
	run.Env = []string{"TURND_URL=" + base}
	if sr := os.Getenv("SystemRoot"); sr != "" {
		run.Env = append(run.Env, "SystemRoot="+sr)
	}
	done := make(chan struct{})
	var out []byte
	go func() { out, err = run.CombinedOutput(); close(done) }()
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		_ = run.Process.Kill()
		t.Fatal("the wasm test hung")
	}
	if err != nil || !strings.Contains(string(out), "--- PASS: TestWasmRoundTrip") {
		t.Fatalf("%v\n%s", err, out)
	}
}
