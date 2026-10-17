package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"

	"mullvad-fastest/internal/relay"
	"mullvad-fastest/internal/scan"
)

func workerMain() int {
	var in struct {
		Relays []relay.Relay `json:"relays"`
	}
	if err := json.NewDecoder(os.Stdin).Decode(&in); err != nil {
		return 1
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	out := bufio.NewWriter(os.Stdout)
	enc := json.NewEncoder(out)
	scan.Run(ctx, in.Relays, nil, func(ev scan.Event) {
		if err := enc.Encode(ev); err != nil {
			cancel()
			return
		}
		if err := out.Flush(); err != nil {
			cancel()
		}
	})
	return 0
}

// spawnWorker runs the scan in a fresh process so it can be excluded from
// the Mullvad tunnel. Events are forwarded as they arrive.
func spawnWorker(ctx context.Context, relays []relay.Relay, emit func(scan.Event)) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, exe, "worker")
	hideCmd(cmd)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		return err
	}

	go func() {
		defer stdin.Close()
		_ = json.NewEncoder(stdin).Encode(struct {
			Relays []relay.Relay `json:"relays"`
		}{Relays: relays})
	}()

	dec := json.NewDecoder(stdout)
	saw := false
	var waitErr error
	waited := false
	wait := func() {
		if !waited {
			waitErr = cmd.Wait()
			waited = true
		}
	}
	for {
		var ev scan.Event
		if err := dec.Decode(&ev); err != nil {
			wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			if saw {
				return nil
			}
			if waitErr != nil {
				return waitErr
			}
			return err
		}
		saw = true
		emit(ev)
		if ev.Type == "done" || ev.Type == "stopped" || ev.Type == "error" {
			wait()
			return nil
		}
	}
}
