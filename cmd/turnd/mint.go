package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/go-turn/turn/creds"
	"github.com/go-turn/turn/session"
	"github.com/spf13/cobra"
)

// MaxMintTTL caps the lifetime of credentials minted by hand: an operator tool
// for proving a deployment, not a way to hand out long-lived access.
const MaxMintTTL = time.Hour

// mintCmd is `turnd mint-credentials`: it mints TURN credentials with the same
// keyring turnd verifies with, so a deployed relay can be exercised (see
// cmd/turnprobe) without an OpenID Connect login. The username goes to stdout;
// the password goes to a new 0600 file, never to stdout or the command line.
func mintCmd() *cobra.Command {
	var (
		secretFiles []string
		subject     string
		ttl         time.Duration
		passwordOut string
	)
	cmd := &cobra.Command{
		Use:   "mint-credentials",
		Short: "mint ephemeral TURN credentials for checking a deployment",
		Long: "Mint TURN credentials with the keyring turnd uses (the first --turn-secret-file signs).\n" +
			"The username is printed on stdout; the password is written to --password-out\n" +
			"(mode 0600, refused if the file exists), never printed.",
		SilenceUsage: true,
		Args:         cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runMint(cmd, mintOptions{secretFiles, subject, ttl, passwordOut, time.Now})
		},
	}
	f := cmd.Flags()
	f.StringArrayVar(&secretFiles, "turn-secret-file", nil, "file holding a TURN REST HMAC secret of 16+ bytes; the first signs (repeat as turnd is given them)")
	f.StringVar(&subject, "subject", "", "opaque subject embedded in the username (no spaces or control characters, at most 128 bytes)")
	f.DurationVar(&ttl, "ttl", 10*time.Minute, "lifetime of the credentials (at most 1h)")
	f.StringVar(&passwordOut, "password-out", "", "new file receiving the password (mode 0600; must not exist)")
	return cmd
}

type mintOptions struct {
	SecretFiles []string
	Subject     string
	TTL         time.Duration
	PasswordOut string
	Now         func() time.Time
}

func runMint(cmd *cobra.Command, o mintOptions) error {
	if len(o.SecretFiles) == 0 {
		return errors.New("missing required flag --turn-secret-file")
	}
	if o.PasswordOut == "" {
		return errors.New("missing required flag --password-out")
	}
	if !session.ValidSubject(o.Subject) {
		return fmt.Errorf("--subject: want 1 to %d bytes of UTF-8 without spaces or control characters", session.MaxSubjectLen)
	}
	if o.TTL <= 0 || o.TTL > MaxMintTTL {
		return fmt.Errorf("--ttl %v: want more than 0 and at most %v", o.TTL, MaxMintTTL)
	}
	secrets, err := readSecrets(o.SecretFiles)
	if err != nil {
		return fmt.Errorf("TURN secret: %w", err)
	}
	ring, err := creds.NewKeyring(secrets[0], secrets[1:]...)
	if err != nil {
		return err
	}
	username, password := ring.Mint(o.Subject, o.Now().Add(o.TTL))
	// The relay refuses a username Parse refuses; fail here, not at the probe.
	if _, _, ok := creds.Parse(username); !ok {
		return errors.New("the minted username is not one the relay accepts")
	}
	f, err := os.OpenFile(o.PasswordOut, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("--password-out: %w", err)
	}
	if _, err := f.WriteString(password + "\n"); err != nil {
		f.Close()
		os.Remove(o.PasswordOut)
		return fmt.Errorf("--password-out: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(o.PasswordOut)
		return fmt.Errorf("--password-out: %w", err)
	}
	fmt.Fprintln(cmd.OutOrStdout(), username)
	return nil
}
