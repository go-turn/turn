package main

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/go-turn/turn/creds"
)

func writeSecretFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func runMintCmd(args ...string) (stdout, stderr string, err error) {
	var out, errb bytes.Buffer
	cmd := RootCmd()
	cmd.SetOut(&out)
	cmd.SetErr(&errb)
	cmd.SetArgs(append([]string{"mint-credentials"}, args...))
	err = cmd.Execute()
	return out.String(), errb.String(), err
}

const (
	secretA = "0123456789abcdef-secret-A"
	secretB = "fedcba9876543210-secret-B"
)

// The credentials minted by the command verify through the Auth hook the relay
// is given (the keyring built from the same secret files), and the password is
// in the file, not on stdout.
func TestMintCredentialsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	a := writeSecretFile(t, dir, "a.secret", secretA+"\n", 0o600)
	b := writeSecretFile(t, dir, "b.secret", secretB+"\n", 0o600)
	pw := filepath.Join(dir, "pw")
	stdout, stderr, err := runMintCmd("--turn-secret-file", a, "--turn-secret-file", b,
		"--subject", "probe", "--ttl", "10m", "--password-out", pw)
	if err != nil {
		t.Fatalf("%v (stderr %q)", err, stderr)
	}
	username := strings.TrimSuffix(stdout, "\n")
	if strings.Contains(username, "\n") || username == "" {
		t.Fatalf("stdout %q is not one username line", stdout)
	}
	raw, err := os.ReadFile(pw)
	if err != nil {
		t.Fatal(err)
	}
	password := strings.TrimSuffix(string(raw), "\n")
	if password == "" || strings.Contains(stdout, password) || strings.Contains(stderr, password) {
		t.Fatalf("password %q missing from the file or leaked (stdout %q, stderr %q)", password, stdout, stderr)
	}
	if runtime.GOOS != "windows" {
		if fi, err := os.Stat(pw); err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("password file mode %v, %v", fi.Mode().Perm(), err)
		}
	}

	// The relay's hook: the keyring turnd builds from the same files.
	secrets, err := readSecrets([]string{a, b})
	if err != nil {
		t.Fatal(err)
	}
	ring, err := creds.NewKeyring(secrets[0], secrets[1:]...)
	if err != nil {
		t.Fatal(err)
	}
	got, ok := ring.Auth(nil)(username)
	if !ok || got != password {
		t.Fatalf("Auth(%q) = %q, %v; want the minted password", username, got, ok)
	}
	exp, sub, ok := creds.Parse(username)
	if !ok || !strings.HasSuffix(sub, ".probe") {
		t.Fatalf("username %q: subject %q", username, sub)
	}
	if d := time.Until(exp); d < 9*time.Minute || d > 10*time.Minute+time.Second {
		t.Fatalf("expires in %v, want about 10m", d)
	}
	// A relay holding a different secret refuses it.
	other, _ := creds.NewKeyring([]byte(secretB))
	if _, ok := other.Auth(nil)(username); ok {
		t.Fatal("a keyring without the signing secret accepted the username")
	}
	// The first file signs: a ring with B first and A second still verifies it.
	rot, _ := creds.NewKeyring([]byte(secretB), []byte(secretA))
	if got, ok := rot.Auth(nil)(username); !ok || got != password {
		t.Fatal("a rotated ring (B current, A previous) refused it")
	}
}

func TestMintCredentialsTTLBoundary(t *testing.T) {
	dir := t.TempDir()
	a := writeSecretFile(t, dir, "a.secret", secretA, 0o600)
	if _, _, err := runMintCmd("--turn-secret-file", a, "--subject", "s", "--ttl", "1h",
		"--password-out", filepath.Join(dir, "pw")); err != nil {
		t.Fatalf("1h is the cap, not over it: %v", err)
	}
}

func TestMintCredentialsRefusals(t *testing.T) {
	dir := t.TempDir()
	good := writeSecretFile(t, dir, "good.secret", secretA, 0o600)
	short := writeSecretFile(t, dir, "short.secret", "tooshort", 0o600)
	empty := writeSecretFile(t, dir, "empty.secret", "\n", 0o600)
	world := writeSecretFile(t, dir, "world.secret", secretA, 0o644)
	existing := writeSecretFile(t, dir, "exists", "keep me", 0o600)
	missing := filepath.Join(dir, "nope.secret")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "elsewhere"), link); err != nil && runtime.GOOS != "windows" {
		t.Fatal(err)
	}
	out := func(n string) string { return filepath.Join(dir, n) }

	cases := []struct {
		name string
		args []string
		want string // substring of the error
	}{
		{"no secret file", []string{"--subject", "s", "--password-out", out("o1")}, "--turn-secret-file"},
		{"no password-out", []string{"--turn-secret-file", good, "--subject", "s"}, "--password-out"},
		{"no subject", []string{"--turn-secret-file", good, "--password-out", out("o2")}, "--subject"},
		{"subject with a space", []string{"--turn-secret-file", good, "--subject", "a b", "--password-out", out("o3")}, "--subject"},
		{"subject with a newline", []string{"--turn-secret-file", good, "--subject", "a\nb", "--password-out", out("o4")}, "--subject"},
		{"subject too long", []string{"--turn-secret-file", good, "--subject", strings.Repeat("a", 129), "--password-out", out("o5")}, "--subject"},
		{"subject not UTF-8", []string{"--turn-secret-file", good, "--subject", "a\xffb", "--password-out", out("o6")}, "--subject"},
		{"ttl zero", []string{"--turn-secret-file", good, "--subject", "s", "--ttl", "0s", "--password-out", out("o7")}, "--ttl"},
		{"ttl negative", []string{"--turn-secret-file", good, "--subject", "s", "--ttl", "-5m", "--password-out", out("o8")}, "--ttl"},
		{"ttl over the cap", []string{"--turn-secret-file", good, "--subject", "s", "--ttl", "1h1s", "--password-out", out("o9")}, "--ttl"},
		{"ttl a day", []string{"--turn-secret-file", good, "--subject", "s", "--ttl", "24h", "--password-out", out("o10")}, "--ttl"},
		{"secret too short", []string{"--turn-secret-file", short, "--subject", "s", "--password-out", out("o11")}, "shorter than 16"},
		{"secret empty", []string{"--turn-secret-file", empty, "--subject", "s", "--password-out", out("o12")}, "empty"},
		{"secret missing", []string{"--turn-secret-file", missing, "--subject", "s", "--password-out", out("o13")}, "no such file"},
		{"secret world-readable", []string{"--turn-secret-file", world, "--subject", "s", "--password-out", out("o14")}, "readable by everybody"},
		{"a second secret is bad", []string{"--turn-secret-file", good, "--turn-secret-file", short, "--subject", "s", "--password-out", out("o15")}, "shorter than 16"},
		{"duplicate secrets", []string{"--turn-secret-file", good, "--turn-secret-file", good, "--subject", "s", "--password-out", out("o16")}, "same"},
		{"password-out exists", []string{"--turn-secret-file", good, "--subject", "s", "--password-out", existing}, "exist"},
		{"stray argument", []string{"--turn-secret-file", good, "--subject", "s", "--password-out", out("o17"), "extra"}, "unknown command"},
		{"password-out in a missing directory", []string{"--turn-secret-file", good, "--subject", "s", "--password-out", filepath.Join(dir, "no", "such", "pw")}, "--password-out"},
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct {
			name string
			args []string
			want string
		}{"password-out is a dangling symlink", []string{"--turn-secret-file", good, "--subject", "s", "--password-out", link}, "exist"})
	}
	for _, c := range cases {
		stdout, _, err := runMintCmd(c.args...)
		if err == nil {
			t.Errorf("%s: accepted", c.name)
			continue
		}
		if !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %q does not mention %q", c.name, err, c.want)
		}
		if stdout != "" {
			t.Errorf("%s: printed %q on a refusal", c.name, stdout)
		}
	}
	if b, _ := os.ReadFile(existing); string(b) != "keep me" {
		t.Errorf("an existing --password-out was overwritten: %q", b)
	}
	if _, err := os.Lstat(filepath.Join(dir, "elsewhere")); err == nil {
		t.Error("a symlink --password-out was followed")
	}
	for i := 1; i <= 17; i++ {
		if _, err := os.Stat(out("o" + strconv.Itoa(i))); err == nil {
			t.Errorf("a refused run left o%d behind", i)
		}
	}
}
