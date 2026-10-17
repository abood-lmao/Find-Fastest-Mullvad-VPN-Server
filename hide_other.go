//go:build !windows

package main

import "os/exec"

func hideCmd(cmd *exec.Cmd) {}
