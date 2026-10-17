package scan

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"

	"mullvad-fastest/internal/relay"
)

func TestChooseCities(t *testing.T) {
	got := ChooseCities([]CitySample{
		{Key: "ch/zrh", MS: 73},
		{Key: "es/bcn", MS: 76},
		{Key: "fr/bod", MS: 81},
		{Key: "de/ber", MS: 91},
		{Key: "gb/glw", MS: 97},
		{Key: "se/got", MS: 98},
		{Key: "fi/hel", MS: 120},
		{Key: "jp/osa", MS: 320},
	})
	if len(got) != 5 {
		t.Fatalf("want 5 cities, got %v", got)
	}
	if got[0] != "ch/zrh" || got[4] != "gb/glw" {
		t.Fatalf("order: %v", got)
	}
	if len(ChooseCities(nil)) != 0 {
		t.Fatal("empty")
	}
}

func TestRunSkipsDistantCities(t *testing.T) {
	var relays []relay.Relay
	latency := map[string]float64{}
	for c := 0; c < 10; c++ {
		base := float64(10 + c*40)
		code := string(rune('a' + c))
		for n := 0; n < 4; n++ {
			ip := "10.0." + strconv.Itoa(c) + "." + strconv.Itoa(n+1)
			host := code + "-cty-wg-00" + strconv.Itoa(n+1)
			relays = append(relays, relay.Relay{
				Hostname:    host,
				IP:          ip,
				Country:     code,
				CountryCode: code,
				City:        "City",
				CityCode:    "cty",
			})
			latency[ip] = base + float64(n)
		}
	}

	var mu sync.Mutex
	calls := map[string]int{}
	measure := func(ctx context.Context, ip net.IP, pings int) (float64, string, bool) {
		mu.Lock()
		calls[ip.String()]++
		mu.Unlock()
		return latency[ip.String()], "icmp", true
	}

	var winner string
	var best float64
	Run(context.Background(), relays, measure, func(ev Event) {
		if ev.Type != "result" {
			return
		}
		if winner == "" || ev.MS < best {
			best = ev.MS
			winner = ev.Hostname
		}
	})
	if winner != "a-cty-wg-001" {
		t.Fatalf("winner %s (%.1f)", winner, best)
	}

	mu.Lock()
	defer mu.Unlock()
	if calls["10.0.0.3"] < 2 {
		t.Fatalf("winning city sample should be probed twice, got %d", calls["10.0.0.3"])
	}
	if calls["10.0.0.1"] != 1 {
		t.Fatalf("other server in the winning city should be probed once, got %d", calls["10.0.0.1"])
	}
	if calls["10.0.9.3"] != 1 {
		t.Fatalf("distant city should only be sampled, got %d", calls["10.0.9.3"])
	}
	if calls["10.0.9.2"] != 0 {
		t.Fatalf("distant extra server should not be probed, got %d", calls["10.0.9.2"])
	}
}
