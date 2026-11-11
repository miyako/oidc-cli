package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/miyako/oidc-cli/internal/auth"
)

type response struct {
	ProtocolVersion int  `json:"protocol_version"`
	OK              bool `json:"ok"`
	*auth.Result
	Error   *auth.Error `json:"error,omitempty"`
	Version string      `json:"version,omitempty"`
}

func main() { os.Exit(execute()) }

func emit(r response, status int) int {
	r.ProtocolVersion = 1
	if json.NewEncoder(os.Stdout).Encode(r) != nil {
		return 10
	}
	return status
}

func failed(code, message string, status int) int {
	return emit(response{Error: &auth.Error{Code: code, Message: message}}, status)
}

func execute() int {
	if len(os.Args) != 2 {
		return failed("invalid_input", "usage: oidc-cli authenticate | version", 2)
	}
	if os.Args[1] == "version" {
		return emit(response{OK: true, Version: version}, 0)
	}
	if os.Args[1] != "authenticate" {
		return failed("invalid_input", "unknown command", 2)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// Read in a goroutine so termination is honored even if a parent leaves stdin open.
	type input struct {
		data []byte
		err  error
	}
	in := make(chan input, 1)
	go func() {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 65537))
		in <- input{b, err}
	}()
	var data []byte
	select {
	case <-ctx.Done():
		return failed("cancelled", "authentication cancelled", 5)
	case v := <-in:
		if v.err != nil || len(v.data) > 65536 || !utf8.Valid(v.data) {
			return failed("invalid_input", "stdin must contain at most 65536 bytes of UTF-8 JSON", 2)
		}
		data = v.data
	}
	c, err := decodeConfig(data)
	if err != nil {
		return failed("invalid_input", "stdin must contain one JSON configuration object with known fields", 2)
	}
	if err := c.Validate(); err != nil {
		var e *auth.Error
		errors.As(err, &e)
		return emit(response{Error: e}, 2)
	}
	if c.ParentPID > 0 {
		alive, closeParent, err := watchParent(c.ParentPID)
		if err != nil {
			return failed("invalid_input", "parent_pid must identify an accessible live process", 2)
		}
		parentCtx, cancel := context.WithCancel(ctx)
		ctx = parentCtx
		parentDone := make(chan struct{})
		defer func() {
			cancel()
			<-parentDone
			closeParent()
		}()
		go func() {
			defer close(parentDone)
			ticker := time.NewTicker(250 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					if !alive() {
						cancel()
						return
					}
				}
			}
		}()
	}
	result, err := auth.Run(ctx, c, auth.Options{Browser: func(ctx context.Context, target string) error {
		if c.OpenBrowser != nil && !*c.OpenBrowser {
			return json.NewEncoder(os.Stderr).Encode(struct {
				ProtocolVersion int    `json:"protocol_version"`
				Event           string `json:"event"`
				URL             string `json:"authorization_url"`
			}{1, "authorization_required", target})
		}
		var command string
		var args []string
		switch runtime.GOOS {
		case "darwin":
			command, args = "open", []string{target}
		case "windows":
			command, args = "rundll32.exe", []string{"url.dll,FileProtocolHandler", target}
		default:
			command, args = "xdg-open", []string{target}
		}
		return exec.CommandContext(ctx, command, args...).Run()
	}})
	if err == nil {
		return emit(response{OK: true, Result: result}, 0)
	}
	var e *auth.Error
	if !errors.As(err, &e) {
		return failed("internal_error", "authentication failed", 10)
	}
	status := 3
	switch e.Code {
	case "invalid_input":
		status = 2
	case "timeout":
		status = 4
	case "cancelled":
		status = 5
	case "internal_error":
		status = 10
	}
	return emit(response{Error: e}, status)
}
