package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"mullvad-fastest/internal/mullvad"
	"mullvad-fastest/internal/relay"
	"mullvad-fastest/internal/scan"
)

//go:embed web/index.html
var page []byte

var hostnameRE = regexp.MustCompile(`^[a-z]{2}-[a-z0-9]+-wg-\d{3}$`)

type hub struct {
	mu   sync.Mutex
	buf  [][]byte
	subs map[chan []byte]struct{}
}

func newHub() *hub {
	return &hub{subs: map[chan []byte]struct{}{}}
}

func (h *hub) reset() {
	h.mu.Lock()
	h.buf = nil
	h.mu.Unlock()
}

func (h *hub) publish(ev scan.Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.buf = append(h.buf, b)
	if len(h.buf) > 800 {
		h.buf = h.buf[len(h.buf)-800:]
	}
	for ch := range h.subs {
		select {
		case ch <- b:
		default:
		}
	}
}

func (h *hub) subscribe() (snapshot [][]byte, ch chan []byte, cancel func()) {
	ch = make(chan []byte, 1024)
	h.mu.Lock()
	snapshot = append([][]byte(nil), h.buf...)
	h.subs[ch] = struct{}{}
	h.mu.Unlock()
	cancel = func() {
		h.mu.Lock()
		delete(h.subs, ch)
		h.mu.Unlock()
	}
	return snapshot, ch, cancel
}

type app struct {
	hub      *hub
	mu       sync.Mutex
	scanning bool
	cancel   context.CancelFunc
	stop     func()
}

func newApp(stop func()) *app {
	return &app{hub: newHub(), stop: stop}
}

func (a *app) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.servePage)
	mux.HandleFunc("GET /api/health", a.health)
	mux.HandleFunc("GET /api/meta", a.meta)
	mux.HandleFunc("GET /api/status", a.status)
	mux.HandleFunc("GET /api/events", a.events)
	mux.HandleFunc("POST /api/scan", a.startScan)
	mux.HandleFunc("POST /api/stop", a.stopScan)
	mux.HandleFunc("POST /api/connect", a.connect)
	mux.HandleFunc("POST /api/disconnect", a.disconnect)
	mux.HandleFunc("POST /api/shutdown", a.shutdown)
	return mux
}

func (a *app) servePage(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(page)
}

func (a *app) health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "version": version})
}

func (a *app) meta(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	relays, err := relay.Load(ctx)
	status, _ := mullvad.GetStatus(ctx)
	body := map[string]any{"status": status}
	if err != nil {
		body["error"] = "Couldn't reach the Mullvad relay list."
		writeJSON(w, http.StatusBadGateway, body)
		return
	}
	body["countries"] = relay.Countries(relays)
	body["relays"] = len(relays)
	writeJSON(w, http.StatusOK, body)
}

func (a *app) status(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()
	st, _ := mullvad.GetStatus(ctx)
	writeJSON(w, http.StatusOK, st)
}

func (a *app) events(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming is not supported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	snap, ch, cancel := a.hub.subscribe()
	defer cancel()
	for _, b := range snap {
		if err := writeEvent(w, flusher, b); err != nil {
			return
		}
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case b := <-ch:
			if err := writeEvent(w, flusher, b); err != nil {
				return
			}
		}
	}
}

func writeEvent(w http.ResponseWriter, flusher http.Flusher, b []byte) error {
	if _, err := w.Write([]byte("data: ")); err != nil {
		return err
	}
	if _, err := w.Write(b); err != nil {
		return err
	}
	if _, err := w.Write([]byte("\n\n")); err != nil {
		return err
	}
	flusher.Flush()
	return nil
}

func (a *app) startScan(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Country string `json:"country"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil && !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "Bad request.")
		return
	}

	ctx, cancelLoad := context.WithTimeout(r.Context(), 15*time.Second)
	relays, err := relay.Load(ctx)
	cancelLoad()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "Couldn't reach the Mullvad relay list.")
		return
	}
	list, err := relay.Filter(relays, body.Country)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	a.mu.Lock()
	if a.scanning {
		a.mu.Unlock()
		writeErr(w, http.StatusConflict, "A scan is already running.")
		return
	}
	scanCtx, cancel := context.WithCancel(context.Background())
	a.scanning = true
	a.cancel = cancel
	a.mu.Unlock()

	a.hub.reset()
	a.hub.publish(scan.Event{Type: "start"})
	go func() {
		defer func() {
			a.mu.Lock()
			a.scanning = false
			a.cancel = nil
			a.mu.Unlock()
			cancel()
		}()
		executeScan(scanCtx, list, a.hub.publish)
	}()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) stopScan(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	cancel := a.cancel
	a.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (a *app) connect(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hostname string `json:"hostname"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "Bad request.")
		return
	}
	host := strings.ToLower(strings.TrimSpace(body.Hostname))
	if !hostnameRE.MatchString(host) {
		writeErr(w, http.StatusBadRequest, "Unknown server.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	relays, err := relay.Load(ctx)
	cancel()
	if err != nil {
		writeErr(w, http.StatusBadGateway, "Couldn't reach the Mullvad relay list.")
		return
	}
	if _, ok := relay.ByHostname(relays, host); !ok {
		writeErr(w, http.StatusBadRequest, "Unknown server.")
		return
	}

	ctx, cancel = context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	st, err := mullvad.Connect(ctx, host)
	if err != nil && st.State == "" {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *app) disconnect(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	st, err := mullvad.Disconnect(ctx)
	if err != nil && st.State == "" {
		writeErr(w, http.StatusBadGateway, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, st)
}

func (a *app) shutdown(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	if a.stop != nil {
		go a.stop()
	}
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}
