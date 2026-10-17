//go:build !windows

package probe

import (
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"time"
)

var timeRE = regexp.MustCompile(`time[=<]([0-9.]+)\s*ms`)

func pingOnce(ip net.IP, timeout time.Duration) (float64, bool) {
	ip = ip.To4()
	if ip == nil || timeout <= 0 {
		return 0, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout+700*time.Millisecond)
	defer cancel()

	var args []string
	if runtime.GOOS == "darwin" {
		wait := int(timeout / time.Millisecond)
		if wait < 1 {
			wait = 1
		}
		args = []string{"-c", "1", "-W", strconv.Itoa(wait), ip.String()}
	} else {
		sec := int((timeout + time.Second - 1) / time.Second)
		if sec < 1 {
			sec = 1
		}
		args = []string{"-c", "1", "-W", strconv.Itoa(sec), ip.String()}
	}

	out, err := exec.CommandContext(ctx, "ping", args...).CombinedOutput()
	if err != nil && len(out) == 0 {
		return 0, false
	}
	m := timeRE.FindSubmatch(out)
	if m == nil {
		return 0, false
	}
	ms, err := strconv.ParseFloat(string(m[1]), 64)
	if err != nil {
		return 0, false
	}
	return ms, true
}
