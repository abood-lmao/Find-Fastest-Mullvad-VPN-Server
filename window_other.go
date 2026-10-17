//go:build !windows

package main

import (
	"fmt"
	"os/exec"
	"runtime"
)

func openAppWindow(url string) (*exec.Cmd, func(), error) {
	return nil, nil, fmt.Errorf("app window is windows-only")
}

func openBrowser(url string) {
	switch runtime.GOOS {
	case "darwin":
		_ = exec.Command("open", url).Start()
	default:
		_ = exec.Command("xdg-open", url).Start()
	}
}
