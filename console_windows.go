//go:build windows

package main

import (
	"os"
	"syscall"
)

// attachConsole makes prints show up for a windowless exe.
// A redirected handle is kept. A console is attached only when a handle is missing,
// which is what happens when the exe is started from Command Prompt.
func attachConsole() {
	out, outOK := stdHandle(syscall.STD_OUTPUT_HANDLE)
	errH, errOK := stdHandle(syscall.STD_ERROR_HANDLE)
	if outOK {
		os.Stdout = reopen(out, "stdout")
	}
	if errOK {
		os.Stderr = reopen(errH, "stderr")
	}
	if outOK && errOK {
		return
	}

	kernel := syscall.NewLazyDLL("kernel32.dll")
	r, _, _ := kernel.NewProc("AttachConsole").Call(^uintptr(0))
	if r == 0 {
		return
	}
	if !outOK {
		if h, ok := stdHandle(syscall.STD_OUTPUT_HANDLE); ok {
			os.Stdout = reopen(h, "stdout")
		}
	}
	if !errOK {
		if h, ok := stdHandle(syscall.STD_ERROR_HANDLE); ok {
			os.Stderr = reopen(h, "stderr")
		}
	}
}

func reopen(h syscall.Handle, name string) *os.File {
	var dup syscall.Handle
	proc, err := syscall.GetCurrentProcess()
	if err != nil {
		return os.NewFile(uintptr(h), name)
	}
	err = syscall.DuplicateHandle(proc, h, proc, &dup, 0, false, syscall.DUPLICATE_SAME_ACCESS)
	if err != nil {
		return os.NewFile(uintptr(h), name)
	}
	return os.NewFile(uintptr(dup), name)
}

func stdHandle(which int) (syscall.Handle, bool) {
	h, err := syscall.GetStdHandle(which)
	if err != nil || h == 0 || h == syscall.InvalidHandle {
		return 0, false
	}
	return h, true
}
