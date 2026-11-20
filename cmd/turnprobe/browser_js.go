//go:build js

package main

import (
	"context"
	"errors"
	"io"
	"time"
)

// startBrowser: there is no Chrome to start from a js/wasm program.
func startBrowser(context.Context, io.Writer, []target, string, string, bool, string, time.Duration) error {
	return errors.New("--browser is not available on js/wasm")
}
