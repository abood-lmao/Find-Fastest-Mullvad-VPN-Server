//go:build !windows

package mullvad

import "os/exec"

func hide(cmd *exec.Cmd) {}
