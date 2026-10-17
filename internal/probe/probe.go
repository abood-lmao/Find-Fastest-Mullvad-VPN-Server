// Package probe times a path to a relay.
// ICMP echo is the measurement. A TCP handshake to port 443 is used only
// when a relay does not answer ping.
package probe

import (
	"context"
	"net"
	"time"
)

const (
	// Parallel is how many probes run at once.
	Parallel = 48
	payload  = 32
)

// Measure returns a round-trip time in milliseconds.
// pings is how many ICMP echoes to average. A failed first echo falls
// through to a single TCP connect on port 443.
func Measure(ctx context.Context, ip net.IP, pings int, icmpTimeout, tcpTimeout time.Duration) (float64, string, bool) {
	if ip = ip.To4(); ip == nil {
		return 0, "", false
	}
	if pings < 1 {
		pings = 1
	}
	if ctx.Err() != nil {
		return 0, "", false
	}

	var sum float64
	var n int
	for i := 0; i < pings; i++ {
		if ctx.Err() != nil {
			break
		}
		ms, ok := pingOnce(ip, icmpTimeout)
		if !ok {
			if n > 0 {
				break
			}
			ms, ok = tcpOnce(ctx, ip, tcpTimeout)
			if !ok {
				return 0, "", false
			}
			return ms, "tcp", true
		}
		sum += ms
		n++
	}
	if n == 0 {
		return 0, "", false
	}
	return sum / float64(n), "icmp", true
}

func tcpOnce(ctx context.Context, ip net.IP, timeout time.Duration) (float64, bool) {
	if timeout <= 0 {
		timeout = 400 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", ip.String()+":443")
	if err != nil {
		return 0, false
	}
	elapsed := time.Since(start)
	conn.Close()
	if elapsed <= 0 {
		return 0, false
	}
	return float64(elapsed.Microseconds()) / 1000, true
}
