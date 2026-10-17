//go:build windows

package mullvad

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

type saved struct {
	Added   string `json:"added"`
	TurnOff bool   `json:"turn_off"`
	PID     int    `json:"pid"`
}

func statePath() string {
	return filepath.Join(os.TempDir(), "mullvad-fastest-tunnel.json")
}

// Borrow makes a newly started copy of this program leave the tunnel.
// The returned function restores the previous split-tunnel settings.
// direct is true when pings from a new process will use the real network.
func Borrow(ctx context.Context) (func(), bool, error) {
	st, err := GetStatus(ctx)
	connected := err == nil && (strings.HasPrefix(st.State, "Connected") || strings.HasPrefix(st.State, "Connecting"))
	if !connected {
		return func() {}, true, nil
	}
	return borrowConnected(ctx)
}

func borrowConnected(ctx context.Context) (func(), bool, error) {
	on, apps, err := splitState(ctx)
	if err != nil {
		return func() {}, false, err
	}
	exe, err := os.Executable()
	if err != nil {
		return func() {}, false, err
	}
	exe = filepath.Clean(exe)

	undoState := saved{PID: os.Getpid(), TurnOff: !on}
	if exact(apps, exe) == "" {
		undoState.Added = exe
	}
	if undoState.Added == "" && !undoState.TurnOff {
		return func() {}, true, nil
	}
	if err := writeState(undoState); err != nil {
		return func() {}, false, err
	}

	if undoState.Added != "" {
		if _, _, err := run(ctx, "split-tunnel", "app", "add", exe); err != nil {
			_ = os.Remove(statePath())
			return func() {}, false, err
		}
		if _, apps, err := splitState(ctx); err == nil {
			if got := exact(apps, exe); got != "" {
				undoState.Added = got
				_ = writeState(undoState)
			}
		}
	}
	if undoState.TurnOff {
		if _, _, err := run(ctx, "split-tunnel", "set", "on"); err != nil {
			undo(undoState)
			_ = os.Remove(statePath())
			return func() {}, false, err
		}
	}

	var once sync.Once
	return func() {
		once.Do(func() {
			undo(undoState)
			_ = os.Remove(statePath())
		})
	}, true, nil
}

// Recover puts split-tunnel settings back after a crash.
func Recover() {
	st, err := readState()
	if err != nil {
		return
	}
	if st.PID > 0 && st.PID != os.Getpid() && pidAlive(st.PID) {
		return
	}
	undo(st)
	_ = os.Remove(statePath())
}

func undo(st saved) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	if st.Added != "" {
		_, _, _ = run(ctx, "split-tunnel", "app", "remove", st.Added)
	}
	if st.TurnOff {
		_, _, _ = run(ctx, "split-tunnel", "set", "off")
	}
}

func splitState(ctx context.Context) (bool, []string, error) {
	out, _, err := run(ctx, "split-tunnel", "get")
	if err != nil {
		return false, nil, err
	}
	on, apps := parseSplit(out)
	return on, apps, nil
}

func exact(apps []string, exe string) string {
	want := strings.ToLower(filepath.Clean(exe))
	for _, app := range apps {
		if strings.ToLower(filepath.Clean(app)) == want {
			return app
		}
	}
	return ""
}

func writeState(st saved) error {
	buf, err := json.Marshal(st)
	if err != nil {
		return err
	}
	return os.WriteFile(statePath(), buf, 0o600)
}

func readState() (saved, error) {
	buf, err := os.ReadFile(statePath())
	if err != nil {
		return saved{}, err
	}
	var st saved
	err = json.Unmarshal(buf, &st)
	return st, err
}

func pidAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	const processQueryLimited = 0x1000
	h, err := syscall.OpenProcess(processQueryLimited, false, uint32(pid))
	if err != nil {
		return false
	}
	_ = syscall.CloseHandle(h)
	return true
}
