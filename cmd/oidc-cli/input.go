package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/miyako/oidc-cli/internal/auth"
)

func decodeConfig(data []byte) (auth.Config, error) {
	var c auth.Config
	// Reject duplicate keys as well as unknown fields, avoiding parser-dependent configuration.
	d := json.NewDecoder(bytes.NewReader(data))
	t, err := d.Token()
	if err != nil || t != json.Delim('{') {
		return c, errors.New("expected object")
	}
	seen := map[string]bool{}
	for d.More() {
		t, err := d.Token()
		if err != nil {
			return c, err
		}
		key, ok := t.(string)
		if !ok || seen[key] {
			return c, errors.New("duplicate key")
		}
		switch key {
		case "protocol_version", "issuer", "client_id", "scopes", "listen_address", "callback_path",
			"timeout_seconds", "http_timeout_seconds", "open_browser", "allow_insecure_loopback_http",
			"include_tokens", "parent_pid", "success_html", "success_html_file", "failure_html", "failure_html_file":
		default:
			return c, errors.New("unknown field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := d.Decode(&value); err != nil {
			return c, err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return c, errors.New("null field")
		}
	}
	if _, err := d.Token(); err != nil {
		return c, err
	}
	if _, err := d.Token(); err != io.EOF {
		return c, errors.New("trailing data")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	err = d.Decode(&c)
	return c, err
}
