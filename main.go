package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"time"

	"mullvad-fastest/internal/mullvad"
	"mullvad-fastest/internal/relay"
	"mullvad-fastest/internal/scan"
)

const (
	version    = "0.1.0"
	listenAddr = "127.0.0.1:47331"
)

func main() {
	attachConsole()
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) > 0 && args[0] == "worker" {
		return workerMain()
	}
	mullvad.Recover()
	if len(args) == 0 {
		return runGUI()
	}
	switch args[0] {
	case "scan":
		return cmdScan(args[1:])
	case "connect":
		return cmdConnect(args[1:])
	case "disconnect":
		return cmdDisconnect()
	case "status":
		return cmdStatus()
	case "version", "-V", "--version":
		fmt.Println("mullvad-fastest", version)
		return 0
	case "help", "-h", "--help":
		usage()
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage()
		return 2
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, `mullvad-fastest finds the fastest Mullvad WireGuard server.

Usage:
  mullvad-fastest                       Open the window
  mullvad-fastest scan [-country se]    Print the fastest servers
  mullvad-fastest connect <hostname>    Connect to one server
  mullvad-fastest disconnect            Disconnect
  mullvad-fastest status                Show the tunnel status

scan flags:
  -country code   Limit the scan to one country
  -top n          How many results to print (default 15)
  -json           Print the results as JSON
`)
}

type row struct {
	Hostname string  `json:"hostname"`
	City     string  `json:"city"`
	Country  string  `json:"country"`
	Code     string  `json:"code"`
	MS       float64 `json:"ms"`
	Method   string  `json:"method"`
}

func cmdScan(args []string) int {
	fs := flag.NewFlagSet("scan", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	country := fs.String("country", "", "two-letter country code")
	top := fs.Int("top", 15, "how many servers to print")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *top < 1 {
		*top = 1
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	relays, err := relay.Load(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	list, err := relay.Filter(relays, *country)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}

	var rows []row
	index := map[string]int{}
	var last scan.Event
	executeScan(ctx, list, func(ev scan.Event) {
		switch ev.Type {
		case "info":
			fmt.Fprintf(os.Stderr, "\n%s\n", ev.Text)
		case "phase", "progress":
			if ev.Total > 0 {
				fmt.Fprintf(os.Stderr, "\r%-44s %3d/%d", ev.Text, ev.Done, ev.Total)
			}
		case "result":
			if i, ok := index[ev.Hostname]; ok {
				rows[i].MS = ev.MS
				rows[i].Method = ev.Method
				return
			}
			index[ev.Hostname] = len(rows)
			rows = append(rows, row{
				Hostname: ev.Hostname,
				City:     ev.City,
				Country:  ev.Country,
				Code:     ev.Code,
				MS:       ev.MS,
				Method:   ev.Method,
			})
		case "done", "stopped", "error":
			last = ev
		}
	})
	fmt.Fprintln(os.Stderr)

	if last.Type == "error" {
		if last.Message != "" {
			fmt.Fprintln(os.Stderr, last.Message)
		}
		return 1
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "No servers answered.")
		return 1
	}
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].MS < rows[j].MS })
	if *asJSON {
		n := *top
		if n > len(rows) {
			n = len(rows)
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(rows[:n])
		return 0
	}

	best := rows[0]
	fmt.Printf("Fastest  %s  %s  %s, %s\n\n", best.Hostname, formatMS(best.MS), best.City, best.Country)
	n := *top
	if n > len(rows) {
		n = len(rows)
	}
	for _, item := range rows[:n] {
		fmt.Printf("%7s  %-4s  %-18s  %s, %s\n", formatMS(item.MS), item.Method, item.Hostname, item.City, item.Country)
	}
	if last.Elapsed > 0 {
		fmt.Printf("\n%d answered in %s\n", len(rows), time.Duration(last.Elapsed)*time.Millisecond)
	}
	if last.Type == "stopped" {
		return 130
	}
	return 0
}

func cmdConnect(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: mullvad-fastest connect <hostname>")
		return 2
	}
	host := strings.ToLower(args[0])
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	relays, err := relay.Load(ctx)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, ok := relay.ByHostname(relays, host); !ok || !hostnameRE.MatchString(host) {
		fmt.Fprintf(os.Stderr, "unknown server %q\n", host)
		return 1
	}
	st, err := mullvad.Connect(ctx, host)
	if err != nil && !strings.HasPrefix(st.State, "Connected") {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("%s\n%s\n%s\n", st.State, st.Relay, st.Location)
	return 0
}

func cmdDisconnect() int {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := mullvad.Disconnect(ctx)
	if err != nil && !strings.HasPrefix(st.State, "Disconnected") {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println(st.State)
	return 0
}

func cmdStatus() int {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	st, _ := mullvad.GetStatus(ctx)
	fmt.Println(st.State)
	if st.Relay != "" {
		fmt.Println(st.Relay)
	}
	if st.Location != "" {
		fmt.Println(st.Location)
	}
	return 0
}

func formatMS(ms float64) string {
	if ms < 1 {
		return "<1 ms"
	}
	return fmt.Sprintf("%d ms", int(math.Round(ms)))
}

func executeScan(ctx context.Context, relays []relay.Relay, emit func(scan.Event)) {
	st, _ := mullvad.GetStatus(ctx)
	connected := strings.HasPrefix(st.State, "Connected") || strings.HasPrefix(st.State, "Connecting")
	undo, direct, err := mullvad.Borrow(ctx)
	defer undo()
	if err != nil {
		emit(scan.Event{Type: "info", Text: "Couldn't measure outside the tunnel. Times may be off."})
	} else if connected && direct {
		emit(scan.Event{Type: "info", Text: "Measuring outside the tunnel."})
	} else if connected && !direct {
		emit(scan.Event{Type: "info", Text: "You're connected, so these times go through the tunnel. Disconnect for a real reading."})
	}

	if err := spawnWorker(ctx, relays, emit); err != nil {
		if ctx.Err() != nil {
			emit(scan.Event{Type: "stopped"})
			return
		}
		scan.Run(ctx, relays, nil, emit)
	}
}

func runGUI() int {
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		if healthy() {
			openBrowser("http://" + listenAddr + "/")
			return 0
		}
		fmt.Fprintf(os.Stderr, "%s is already in use\n", listenAddr)
		return 1
	}
	defer ln.Close()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	application := newApp(stop)
	srv := &http.Server{
		Handler:           application.routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shut)
	}()

	url := "http://" + listenAddr + "/"
	win, cleanup, winErr := openAppWindow(url)
	if cleanup != nil {
		defer cleanup()
	}
	if winErr != nil || win == nil {
		openBrowser(url)
		fmt.Fprintln(os.Stderr, url)
		_ = srv.Serve(ln)
		return 0
	}

	go func() { _ = srv.Serve(ln) }()
	_ = win.Wait()
	stop()
	return 0
}

func healthy() bool {
	client := http.Client{Timeout: 400 * time.Millisecond}
	res, err := client.Get("http://" + listenAddr + "/api/health")
	if err != nil {
		return false
	}
	defer res.Body.Close()
	return res.StatusCode == http.StatusOK
}
