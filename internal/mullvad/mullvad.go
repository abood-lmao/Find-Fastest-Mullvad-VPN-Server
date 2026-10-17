// Package mullvad talks to the Mullvad CLI and, on Windows, steps outside
// the tunnel for the duration of a scan.
package mullvad

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// Status is the daemon's current connection.
type Status struct {
	State     string `json:"state"`
	Relay     string `json:"relay,omitempty"`
	Location  string `json:"location,omitempty"`
	Installed bool   `json:"installed"`
}

var (
	binOnce sync.Once
	binPath string
)

// Bin returns the mullvad executable, or "" if it is not installed.
func Bin() string {
	binOnce.Do(func() {
		if p, err := exec.LookPath("mullvad"); err == nil {
			binPath = p
			return
		}
		for _, candidate := range extraBins() {
			info, err := os.Stat(candidate)
			if err == nil && !info.IsDir() {
				binPath = candidate
				return
			}
		}
	})
	return binPath
}

// GetStatus asks the Mullvad CLI. A missing CLI is not an error.
func GetStatus(ctx context.Context) (Status, error) {
	if Bin() == "" {
		return Status{State: "Not installed", Installed: false}, nil
	}
	out, errText, err := run(ctx, "status")
	if err != nil && out == "" {
		state := "Unavailable"
		if strings.Contains(strings.ToLower(errText), "daemon") {
			state = "Daemon not running"
		}
		return Status{State: state, Installed: true}, nil
	}
	st := parseStatus(out)
	st.Installed = true
	return st, nil
}

// Connect selects a hostname and brings the tunnel up on it.
func Connect(ctx context.Context, hostname string) (Status, error) {
	if Bin() == "" {
		return Status{}, fmt.Errorf("Mullvad CLI not found")
	}
	if _, _, err := run(ctx, "relay", "set", "location", hostname); err != nil {
		return Status{}, err
	}
	st, _ := GetStatus(ctx)
	var err error
	if strings.HasPrefix(st.State, "Connected") || strings.HasPrefix(st.State, "Connecting") {
		_, _, err = run(ctx, "reconnect")
	} else {
		_, _, err = run(ctx, "connect")
	}
	if err != nil {
		st, _ = GetStatus(ctx)
		return st, err
	}
	deadline := time.Now().Add(12 * time.Second)
	for {
		st, _ = GetStatus(ctx)
		if st.Relay == hostname && strings.HasPrefix(st.State, "Connected") {
			return st, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return st, ctx.Err()
		}
		time.Sleep(300 * time.Millisecond)
	}
}

// Disconnect tears the tunnel down.
func Disconnect(ctx context.Context) (Status, error) {
	if Bin() == "" {
		return Status{}, fmt.Errorf("Mullvad CLI not found")
	}
	if _, _, err := run(ctx, "disconnect"); err != nil {
		return Status{}, err
	}
	deadline := time.Now().Add(8 * time.Second)
	for {
		st, _ := GetStatus(ctx)
		if strings.HasPrefix(st.State, "Disconnected") {
			return st, nil
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return st, ctx.Err()
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func run(ctx context.Context, args ...string) (string, string, error) {
	bin := Bin()
	if bin == "" {
		return "", "", fmt.Errorf("Mullvad CLI not found")
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	hide(cmd)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	out := strings.TrimSpace(stdout.String())
	errText := strings.TrimSpace(stderr.String())
	if err != nil {
		msg := errText
		if msg == "" {
			msg = out
		}
		if msg == "" {
			msg = err.Error()
		}
		return out, errText, fmt.Errorf("mullvad %s: %s", strings.Join(args, " "), msg)
	}
	return out, errText, nil
}

func parseSplit(out string) (bool, []string) {
	on := false
	var apps []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		lower := strings.ToLower(line)
		if strings.Contains(lower, "state:") {
			on = strings.HasSuffix(lower, " on") || strings.Contains(lower, ": on")
			continue
		}
		if strings.HasPrefix(lower, "excluded") {
			continue
		}
		apps = append(apps, line)
	}
	return on, apps
}

func parseStatus(out string) Status {
	st := Status{}
	lines := strings.Split(out, "\n")
	if len(lines) == 0 || strings.TrimSpace(out) == "" {
		st.State = "Unknown"
		return st
	}
	st.State = strings.TrimSpace(lines[0])
	for _, line := range lines {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Relay:"):
			st.Relay = strings.TrimSpace(strings.TrimPrefix(line, "Relay:"))
		case strings.HasPrefix(line, "Visible location:"):
			loc := strings.TrimSpace(strings.TrimPrefix(line, "Visible location:"))
			if i := strings.Index(loc, ". IPv4"); i >= 0 {
				loc = loc[:i]
			}
			st.Location = strings.TrimSpace(loc)
		}
	}
	return st
}
