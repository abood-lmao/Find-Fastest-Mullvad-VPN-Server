//go:build windows

package probe

import (
	"encoding/binary"
	"net"
	"runtime"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

var (
	iphlp           = syscall.NewLazyDLL("iphlpapi.dll")
	icmpCreateFile  = iphlp.NewProc("IcmpCreateFile")
	icmpCloseHandle = iphlp.NewProc("IcmpCloseHandle")
	icmpSendEcho    = iphlp.NewProc("IcmpSendEcho")
)

const invalidHandle = ^uintptr(0)

var (
	poolOnce sync.Once
	pool     chan uintptr
	poolSize int
	echoData = [payload]byte{
		'f', 'a', 's', 't', 'e', 's', 't', '-',
		'f', 'a', 's', 't', 'e', 's', 't', '-',
		'f', 'a', 's', 't', 'e', 's', 't', '-',
		'f', 'a', 's', 't', 'e', 's', 't', '!',
	}
)

func handles() chan uintptr {
	poolOnce.Do(func() {
		pool = make(chan uintptr, Parallel)
		for i := 0; i < Parallel; i++ {
			h, _, _ := icmpCreateFile.Call()
			if h == 0 || h == invalidHandle {
				continue
			}
			pool <- h
			poolSize++
		}
	})
	return pool
}

func pingOnce(ip net.IP, timeout time.Duration) (float64, bool) {
	ip = ip.To4()
	if ip == nil {
		return 0, false
	}
	h, ok := checkout()
	if !ok {
		return 0, false
	}
	defer func() { handles() <- h }()

	if timeout <= 0 {
		timeout = 500 * time.Millisecond
	}
	ms := timeout.Milliseconds()
	if ms < 1 {
		ms = 1
	}

	dest := binary.LittleEndian.Uint32(ip)
	reply := make([]byte, 256)
	n, _, _ := icmpSendEcho.Call(
		h,
		uintptr(dest),
		uintptr(unsafe.Pointer(&echoData[0])),
		uintptr(len(echoData)),
		0,
		uintptr(unsafe.Pointer(&reply[0])),
		uintptr(len(reply)),
		uintptr(ms),
	)
	runtime.KeepAlive(&reply[0])
	runtime.KeepAlive(&echoData[0])
	if n == 0 {
		return 0, false
	}
	status := binary.LittleEndian.Uint32(reply[4:8])
	if status != 0 {
		return 0, false
	}
	rtt := binary.LittleEndian.Uint32(reply[8:12])
	return float64(rtt), true
}

func checkout() (uintptr, bool) {
	ch := handles()
	if poolSize == 0 {
		return 0, false
	}
	select {
	case h := <-ch:
		if h == 0 || h == invalidHandle {
			return 0, false
		}
		return h, true
	case <-time.After(2 * time.Second):
		return 0, false
	}
}
