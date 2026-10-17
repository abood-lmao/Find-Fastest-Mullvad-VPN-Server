//go:build !windows

package mullvad

import (
	"context"
	"strings"
)

// Borrow reports whether a new probe process will see the real network.
// Split tunneling from this tool is Windows-only.
func Borrow(ctx context.Context) (func(), bool, error) {
	st, err := GetStatus(ctx)
	connected := err == nil && (strings.HasPrefix(st.State, "Connected") || strings.HasPrefix(st.State, "Connecting"))
	if connected {
		return func() {}, false, nil
	}
	return func() {}, true, nil
}

// Recover is a no-op off Windows.
func Recover() {}
