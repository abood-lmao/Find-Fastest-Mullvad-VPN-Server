// Package scan finds the fastest relays without pinging the whole network
// one server at a time.
package scan

import (
	"context"
	"math"
	"net"
	"sort"
	"sync"
	"time"

	"mullvad-fastest/internal/probe"
	"mullvad-fastest/internal/relay"
)

const (
	icmpTimeout = 550 * time.Millisecond
	tcpTimeout  = 400 * time.Millisecond
	// directLimit is small enough that probing every server is faster than
	// sampling cities first.
	directLimit = 28
)

// Event is one progress message. Result events carry a server.
type Event struct {
	Type     string  `json:"type"`
	Text     string  `json:"text,omitempty"`
	Done     int     `json:"done,omitempty"`
	Total    int     `json:"total,omitempty"`
	Hostname string  `json:"hostname,omitempty"`
	City     string  `json:"city,omitempty"`
	Country  string  `json:"country,omitempty"`
	Code     string  `json:"code,omitempty"`
	MS       float64 `json:"ms,omitempty"`
	Method   string  `json:"method,omitempty"`
	OK       int     `json:"ok,omitempty"`
	Fail     int     `json:"fail,omitempty"`
	Elapsed  int     `json:"elapsed_ms,omitempty"`
	Message  string  `json:"message,omitempty"`
}

// Measure times one IP. pings is the number of ICMP echoes to average.
type Measure func(ctx context.Context, ip net.IP, pings int) (ms float64, method string, ok bool)

// DefaultMeasure is the live ICMP probe with a TCP fallback.
func DefaultMeasure(ctx context.Context, ip net.IP, pings int) (float64, string, bool) {
	return probe.Measure(ctx, ip, pings, icmpTimeout, tcpTimeout)
}

// CitySample is one city's best time so far, used to decide who gets a full retest.
type CitySample struct {
	Key string
	MS  float64
}

// ChooseCities keeps the cities close to the winner.
// The cutoff is 25ms or 25% of the best time, whichever is larger, and at most five cities.
func ChooseCities(samples []CitySample) []string {
	if len(samples) == 0 {
		return nil
	}
	sorted := append([]CitySample(nil), samples...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].MS < sorted[j].MS })
	margin := sorted[0].MS * 0.25
	if margin < 25 {
		margin = 25
	}
	limit := sorted[0].MS + margin
	var keys []string
	for _, sample := range sorted {
		if sample.MS <= limit {
			keys = append(keys, sample.Key)
		}
	}
	if len(keys) > 5 {
		keys = keys[:5]
	}
	return keys
}

type agg struct {
	mu sync.Mutex
	m  map[string]*score
}

type score struct {
	icmpSum float64
	icmpN   int
	tcpSum  float64
	tcpN    int
}

func (s *score) value() (float64, string, bool) {
	if s.icmpN > 0 {
		return round1(s.icmpSum / float64(s.icmpN)), "icmp", true
	}
	if s.tcpN > 0 {
		return round1(s.tcpSum / float64(s.tcpN)), "tcp", true
	}
	return 0, "", false
}

func round1(v float64) float64 {
	return math.Round(v*10) / 10
}

func (a *agg) add(host string, ms float64, method string) (float64, string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	s := a.m[host]
	if s == nil {
		s = &score{}
		a.m[host] = s
	}
	if method == "icmp" {
		s.icmpSum += ms
		s.icmpN++
	} else if s.icmpN == 0 {
		s.tcpSum += ms
		s.tcpN++
	}
	return s.value()
}

// Run probes relays and emits results as they arrive.
// Lists larger than directLimit are sampled one server per city, then the
// closest cities are probed in full.
func Run(ctx context.Context, relays []relay.Relay, measure Measure, emit func(Event)) {
	if measure == nil {
		measure = DefaultMeasure
	}
	start := time.Now()
	var emitMu sync.Mutex
	userEmit := emit
	safe := func(ev Event) {
		emitMu.Lock()
		userEmit(ev)
		emitMu.Unlock()
	}
	emit = safe

	if len(relays) == 0 {
		emit(Event{Type: "error", Message: "No servers to test."})
		return
	}

	var okN, failN int
	scores := &agg{m: map[string]*score{}}
	finish := func(stopped bool) {
		kind := "done"
		if stopped || ctx.Err() != nil {
			kind = "stopped"
		}
		emit(Event{
			Type:    kind,
			OK:      okN,
			Fail:    failN,
			Elapsed: int(time.Since(start).Milliseconds()),
		})
	}

	if len(relays) <= directLimit {
		emit(Event{Type: "phase", Text: "Pinging " + itoa(len(relays)) + " servers", Total: len(relays)})
		okN, failN = probeAll(ctx, relays, 2, measure, scores, emit, func(done, total int) {
			emit(Event{Type: "progress", Done: done, Total: total, Text: "Pinging " + itoa(len(relays)) + " servers"})
		})
		finish(false)
		return
	}

	sampleRelays := onePerCity(relays)
	emit(Event{Type: "phase", Text: "Checking " + itoa(len(sampleRelays)) + " cities", Total: len(sampleRelays)})
	ok1, fail1 := probeAll(ctx, sampleRelays, 1, measure, scores, emit, func(done, total int) {
		emit(Event{Type: "progress", Done: done, Total: total, Text: "Checking " + itoa(len(sampleRelays)) + " cities"})
	})
	okN += ok1
	failN += fail1
	if ctx.Err() != nil {
		finish(true)
		return
	}

	var citySamples []CitySample
	for _, r := range sampleRelays {
		scores.mu.Lock()
		s := scores.m[r.Hostname]
		scores.mu.Unlock()
		if s == nil {
			continue
		}
		ms, _, ok := s.value()
		if !ok {
			continue
		}
		citySamples = append(citySamples, CitySample{Key: r.Key(), MS: ms})
	}
	chosen := ChooseCities(citySamples)
	if len(chosen) == 0 {
		finish(false)
		return
	}
	keep := map[string]struct{}{}
	for _, key := range chosen {
		keep[key] = struct{}{}
	}
	var deep []relay.Relay
	for _, r := range relays {
		if _, ok := keep[r.Key()]; ok {
			deep = append(deep, r)
		}
	}
	text := "Retesting " + itoa(len(chosen)) + " closest cities"
	emit(Event{Type: "phase", Text: text, Total: len(deep)})
	ok2, fail2 := probeAll(ctx, deep, 1, measure, scores, emit, func(done, total int) {
		emit(Event{Type: "progress", Done: done, Total: total, Text: text})
	})
	okN += ok2
	failN += fail2
	finish(false)
}

func onePerCity(relays []relay.Relay) []relay.Relay {
	grouped := map[string][]relay.Relay{}
	var order []string
	for _, r := range relays {
		key := r.Key()
		if _, ok := grouped[key]; !ok {
			order = append(order, key)
		}
		grouped[key] = append(grouped[key], r)
	}
	out := make([]relay.Relay, 0, len(order))
	for _, key := range order {
		list := grouped[key]
		out = append(out, list[len(list)/2])
	}
	return out
}

func probeAll(ctx context.Context, relays []relay.Relay, pings int, measure Measure, scores *agg, emit func(Event), progress func(done, total int)) (okN, failN int) {
	total := len(relays)
	if total == 0 {
		return 0, 0
	}
	var wg sync.WaitGroup
	sem := make(chan struct{}, probe.Parallel)
	var mu sync.Mutex
	done := 0
	for _, item := range relays {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(item relay.Relay) {
			defer wg.Done()
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			ip := net.ParseIP(item.IP)
			ms, method, ok := measure(ctx, ip, pings)
			mu.Lock()
			done++
			cur := done
			if ok {
				okN++
			} else {
				failN++
			}
			mu.Unlock()
			if ok {
				avg, method, _ := scores.add(item.Hostname, ms, method)
				emit(Event{
					Type:     "result",
					Hostname: item.Hostname,
					City:     item.City,
					Country:  item.Country,
					Code:     item.CountryCode,
					MS:       avg,
					Method:   method,
				})
			}
			progress(cur, total)
		}(item)
	}
	wg.Wait()
	return okN, failN
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}
