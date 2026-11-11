package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestCLIHelper(t *testing.T) {
	if os.Getenv("OIDC_CLI_TEST_HELPER") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"oidc-cli"}, os.Args[i+1:]...)
			break
		}
	}
	if len(os.Args) > 1 && os.Args[1] == "test-parent" {
		io.Copy(io.Discard, os.Stdin)
		os.Exit(0)
	}
	os.Exit(execute())
}

func cliCommand(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	cmd := exec.CommandContext(ctx, exe, append([]string{"-test.run=^TestCLIHelper$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "OIDC_CLI_TEST_HELPER=1")
	return cmd
}

func checkOutput(t *testing.T, data []byte, err error, code int, want string) {
	t.Helper()
	gotCode := 0
	if e, ok := err.(*exec.ExitError); ok {
		gotCode = e.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	if gotCode != code {
		t.Fatalf("exit %d, want %d; output %s", gotCode, code, data)
	}
	var r response
	d := json.NewDecoder(bytes.NewReader(data))
	if err := d.Decode(&r); err != nil {
		t.Fatalf("invalid stdout: %s (%v)", data, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		t.Fatal("stdout is not exactly one JSON object")
	}
	if r.ProtocolVersion != 1 || r.OK != (code == 0) {
		t.Fatalf("invalid envelope: %+v", r)
	}
	if want != "" && (r.Error == nil || r.Error.Code != want) {
		t.Fatalf("wrong error: %+v", r.Error)
	}
}

func TestCLIProtocol(t *testing.T) {
	for _, tt := range []struct {
		name, command, input string
		exit                 int
		code                 string
	}{
		{"version", "version", "", 0, ""},
		{"command", "unknown", "", 2, "invalid_input"},
		{"empty", "authenticate", "", 2, "invalid_input"},
		{"unknown-field", "authenticate", `{"protocol_version":1,"client_secret":"never-log-this"}`, 2, "invalid_input"},
		{"case", "authenticate", `{"PROTOCOL_VERSION":1}`, 2, "invalid_input"},
		{"null", "authenticate", `{"protocol_version":null}`, 2, "invalid_input"},
		{"oversize", "authenticate", strings.Repeat("x", 65537), 2, "invalid_input"},
		{"utf8", "authenticate", string([]byte{0xff}), 2, "invalid_input"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cmd := cliCommand(t, tt.command)
			cmd.Stdin = strings.NewReader(tt.input)
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			out, err := cmd.Output()
			checkOutput(t, out, err, tt.exit, tt.code)
			if stderr.Len() != 0 || bytes.Contains(out, []byte("never-log-this")) {
				t.Fatal("diagnostics leak input")
			}
		})
	}
}

func discoveryServer(t *testing.T) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"issuer": server.URL, "authorization_endpoint": server.URL + "/authorize",
			"token_endpoint": server.URL + "/token", "jwks_uri": server.URL + "/jwks",
		})
	}))
	t.Cleanup(server.Close)
	return server
}

func startWaitingCLI(t *testing.T, parentPID, timeout int) (*exec.Cmd, *bytes.Buffer) {
	t.Helper()
	server := discoveryServer(t)
	cmd := cliCommand(t, "authenticate")
	cmd.Stdin = strings.NewReader(`{"protocol_version":1,"issuer":"` + server.URL + `","client_id":"desktop","allow_insecure_loopback_http":true,"open_browser":false,"parent_pid":` + strconv.Itoa(parentPID) + `,"timeout_seconds":` + strconv.Itoa(timeout) + `}`)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}
	out := new(bytes.Buffer)
	cmd.Stdout = out
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	var event struct {
		Event string `json:"event"`
		URL   string `json:"authorization_url"`
	}
	if err = json.NewDecoder(stderr).Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.Event != "authorization_required" || !strings.Contains(event.URL, "code_challenge_method=S256") {
		t.Fatalf("invalid event: %+v", event)
	}
	return cmd, out
}

func TestCLIOverallTimeout(t *testing.T) {
	cmd, out := startWaitingCLI(t, 0, 1)
	err := cmd.Wait()
	checkOutput(t, out.Bytes(), err, 4, "timeout")
}

func TestCLISignal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows force termination does not promise a final JSON response")
	}
	for _, sig := range []os.Signal{os.Interrupt, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			cmd, out := startWaitingCLI(t, 0, 10)
			if err := cmd.Process.Signal(sig); err != nil {
				t.Fatal(err)
			}
			err := cmd.Wait()
			checkOutput(t, out.Bytes(), err, 5, "cancelled")
		})
	}
}

func TestCLIParentExit(t *testing.T) {
	parent := cliCommand(t, "test-parent")
	pipe, err := parent.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = parent.Start(); err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	cmd, out := startWaitingCLI(t, parent.Process.Pid, 10)
	if err = pipe.Close(); err != nil {
		t.Fatal(err)
	}
	if err = parent.Wait(); err != nil {
		t.Fatal(err)
	}
	err = cmd.Wait()
	checkOutput(t, out.Bytes(), err, 5, "cancelled")
}
