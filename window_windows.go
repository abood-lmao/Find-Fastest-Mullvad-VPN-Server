//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func findBrowser() string {
	candidates := []string{
		filepath.Join(os.Getenv("ProgramFiles(x86)"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("LocalAppData"), `Microsoft\Edge\Application\msedge.exe`),
		filepath.Join(os.Getenv("ProgramFiles"), `Google\Chrome\Application\chrome.exe`),
		filepath.Join(os.Getenv("LocalAppData"), `Google\Chrome\Application\chrome.exe`),
	}
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if info, err := os.Stat(path); err == nil && !info.IsDir() {
			return path
		}
	}
	return ""
}

func openAppWindow(url string) (*exec.Cmd, func(), error) {
	exe := findBrowser()
	if exe == "" {
		return nil, nil, fmt.Errorf("edge or chrome not found")
	}
	dir := filepath.Join(os.TempDir(), "mullvad-fastest-window")
	_ = os.RemoveAll(dir)
	cmd := exec.Command(exe,
		"--app="+url,
		"--user-data-dir="+dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-sync",
		"--window-size=480,820",
	)
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	return cmd, func() { _ = os.RemoveAll(dir) }, nil
}

func openBrowser(url string) {
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
}
