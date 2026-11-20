// Command turnprobe checks a deployed TURN relay end to end: a STUN Binding,
// then two allocations that permit each other's relayed address and pass a
// datagram across and back. Relaying works if and only if that succeeds, with
// nothing else needed (no browser, no peer, no OpenID Connect login). Mint the
// credentials with `turnd mint-credentials`.
//
//	turnprobe --server 'turn:turn.example.org:3478?transport=udp' \
//	  --server 'turns:turn.example.org:443?transport=tcp' \
//	  --username "$USER" --password-file pw --realm turn.example.org
//
// It prints one line per server, PASS or FAIL with the stage that failed, and
// exits non-zero when any server failed. The password is read from a file,
// never from a flag. A turns: certificate is verified against the system roots
// with SNI set to the host.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

// version is set at build time (-ldflags "-X main.version=v0.3.0").
var version = "dev"

// osExit is replaceable by tests.
var osExit = os.Exit

func main() {
	if err := RootCmd().Execute(); err != nil {
		osExit(1)
	}
}

// probeCfg is replaceable by tests that need a root pool for turns:.
var probeCfg = probeConfig{}

// RootCmd builds the command. Tests drive it with SetArgs, SetOut and SetErr.
func RootCmd() *cobra.Command {
	var (
		servers      []string
		username     string
		passwordFile string
		realm        string
		timeout      time.Duration
		browserMode  bool
		alpn         bool
		chromePath   string
	)
	cmd := &cobra.Command{
		Use:   "turnprobe",
		Short: "prove a TURN relay end to end: Binding, two allocations, a datagram each way",
		Long: "For each --server: send a STUN Binding and print the mapped address, open two\n" +
			"allocations, permit each other's relayed address, send a datagram from relay A to\n" +
			"relay B and back. One PASS or FAIL line per server; exit status 1 if any failed.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: false,
		Args:          cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}
			if alpn && !browserMode {
				return errors.New("--alpn needs --browser")
			}
			if browserMode {
				return runBrowserMode(ctx, cmd.OutOrStdout(), runOptions{servers, username, passwordFile, realm, timeout}, alpn, chromePath)
			}
			return run(ctx, cmd.OutOrStdout(), runOptions{servers, username, passwordFile, realm, timeout})
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&servers, "server", nil, "turn:host:3478?transport=udp|tcp or turns:host:443?transport=tcp (repeat)")
	f.StringVar(&username, "username", "", "TURN username (from `turnd mint-credentials`)")
	f.StringVar(&passwordFile, "password-file", "", "file holding the TURN password")
	f.StringVar(&realm, "realm", "", "the relay's realm (turnd --realm, default the public URL's host)")
	f.DurationVar(&timeout, "timeout", 10*time.Second, "time allowed for each stage")
	f.BoolVar(&browserMode, "browser", false, "ask a headless Chrome instead: an RTCPeerConnection (relay only) must gather a relay candidate; --realm is not needed")
	f.BoolVar(&alpn, "alpn", false, "with --browser: also record the ALPN Chrome offers, against a local TLS listener")
	f.StringVar(&chromePath, "chrome", "", "with --browser: the Chrome binary (default: found on the system)")
	return cmd
}

// runBrowserMode validates the flags of the browser lane and runs it.
func runBrowserMode(ctx context.Context, out io.Writer, o runOptions, alpn bool, chromePath string) error {
	var missing []string
	if len(o.Servers) == 0 {
		missing = append(missing, "--server")
	}
	if o.Username == "" {
		missing = append(missing, "--username")
	}
	if o.PasswordFile == "" {
		missing = append(missing, "--password-file")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	if o.Timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	targets := make([]target, len(o.Servers))
	for i, s := range o.Servers {
		t, err := parseServer(s)
		if err != nil {
			return fmt.Errorf("--server %w", err)
		}
		targets[i] = t
	}
	pw, err := readPassword(o.PasswordFile)
	if err != nil {
		return fmt.Errorf("--password-file: %w", err)
	}
	return startBrowser(ctx, out, targets, o.Username, pw, alpn, chromePath, o.Timeout)
}

type runOptions struct {
	Servers      []string
	Username     string
	PasswordFile string
	Realm        string
	Timeout      time.Duration
}

func run(ctx context.Context, out io.Writer, o runOptions) error {
	var missing []string
	if len(o.Servers) == 0 {
		missing = append(missing, "--server")
	}
	if o.Username == "" {
		missing = append(missing, "--username")
	}
	if o.PasswordFile == "" {
		missing = append(missing, "--password-file")
	}
	if o.Realm == "" {
		missing = append(missing, "--realm")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	if o.Timeout <= 0 {
		return errors.New("--timeout must be positive")
	}
	targets := make([]target, len(o.Servers))
	for i, s := range o.Servers {
		t, err := parseServer(s)
		if err != nil {
			return fmt.Errorf("--server %w", err)
		}
		targets[i] = t
	}
	pw, err := readPassword(o.PasswordFile)
	if err != nil {
		return fmt.Errorf("--password-file: %w", err)
	}
	cr := credentials{Username: o.Username, Password: pw, Realm: o.Realm}
	pc := probeCfg
	pc.Timeout = o.Timeout

	failed := 0
	for _, t := range targets {
		res, err := probe(ctx, t, cr, pc)
		if err != nil {
			failed++
			var se *stageError
			stage, detail := "probe", err.Error()
			if errors.As(err, &se) {
				stage, detail = se.Stage, se.Err.Error()
			}
			mapped := ""
			if res.Mapped.IsValid() {
				mapped = " mapped=" + res.Mapped.String()
			}
			fmt.Fprintf(out, "FAIL %s stage=%s%s: %s\n", t.Raw, stage, mapped, detail)
			continue
		}
		fmt.Fprintf(out, "PASS %s mapped=%s relay-a=%s relay-b=%s roundtrip=%v\n",
			t.Raw, res.Mapped, res.RelayA, res.RelayB, res.RoundTrip.Round(time.Millisecond))
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d servers failed", failed, len(targets))
	}
	return nil
}

// readPassword reads the password file: its content without surrounding
// whitespace. It refuses an empty file and one readable by everybody.
func readPassword(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s: not a regular file", path)
	}
	if runtime.GOOS != "windows" && fi.Mode().Perm()&0o007 != 0 {
		return "", fmt.Errorf("%s: readable by everybody; chmod o-rwx it", path)
	}
	if fi.Size() > 4096 {
		return "", fmt.Errorf("%s: too large for a password", path)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	pw := strings.TrimSpace(string(b))
	if pw == "" {
		return "", fmt.Errorf("%s: empty", path)
	}
	return pw, nil
}
