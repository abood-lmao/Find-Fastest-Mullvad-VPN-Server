// Package relay loads Mullvad's public WireGuard relay list.
package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const endpoint = "https://api.mullvad.net/public/relays/wireguard/v1/"

// Relay is one WireGuard server.
type Relay struct {
	Hostname    string `json:"hostname"`
	IP          string `json:"ip"`
	Country     string `json:"country"`
	CountryCode string `json:"country_code"`
	City        string `json:"city"`
	CityCode    string `json:"city_code"`
}

// Country is a summary row for the picker.
type Country struct {
	Name   string `json:"name"`
	Code   string `json:"code"`
	Cities int    `json:"cities"`
	Relays int    `json:"relays"`
}

// Key groups relays that share a city.
func (r Relay) Key() string {
	return r.CountryCode + "/" + r.CityCode
}

type document struct {
	Countries []struct {
		Name   string `json:"name"`
		Code   string `json:"code"`
		Cities []struct {
			Name   string `json:"name"`
			Code   string `json:"code"`
			Relays []struct {
				Hostname string `json:"hostname"`
				IPv4     string `json:"ipv4_addr_in"`
			} `json:"relays"`
		} `json:"cities"`
	} `json:"countries"`
}

var httpClient = &http.Client{Timeout: 12 * time.Second}

var (
	cacheMu sync.Mutex
	cache   []Relay
	cached  time.Time
)

// Load returns the live relay list, cached for ten minutes.
func Load(ctx context.Context) ([]Relay, error) {
	cacheMu.Lock()
	if cache != nil && time.Since(cached) < 10*time.Minute {
		out := cache
		cacheMu.Unlock()
		return out, nil
	}
	cacheMu.Unlock()

	relays, err := fetch(ctx)
	if err != nil {
		cacheMu.Lock()
		defer cacheMu.Unlock()
		if cache != nil {
			return cache, nil
		}
		return nil, err
	}

	cacheMu.Lock()
	cache = relays
	cached = time.Now()
	cacheMu.Unlock()
	return relays, nil
}

func fetch(ctx context.Context) ([]Relay, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "mullvad-fastest")
	req.Header.Set("Accept", "application/json")

	res, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("reach the Mullvad relay list: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("relay list returned HTTP %d", res.StatusCode)
	}

	var doc document
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("read the relay list: %w", err)
	}
	return Flatten(doc), nil
}

// Flatten turns the API document into a flat slice. Exported for tests via Parse.
func Flatten(doc document) []Relay {
	var out []Relay
	for _, country := range doc.Countries {
		code := strings.ToLower(strings.TrimSpace(country.Code))
		for _, city := range country.Cities {
			cityCode := strings.ToLower(strings.TrimSpace(city.Code))
			for _, item := range city.Relays {
				ip := net.ParseIP(strings.TrimSpace(item.IPv4)).To4()
				host := strings.ToLower(strings.TrimSpace(item.Hostname))
				if ip == nil || host == "" || code == "" || cityCode == "" {
					continue
				}
				out = append(out, Relay{
					Hostname:    host,
					IP:          ip.String(),
					Country:     strings.TrimSpace(country.Name),
					CountryCode: code,
					City:        strings.TrimSpace(city.Name),
					CityCode:    cityCode,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Country != out[j].Country {
			return out[i].Country < out[j].Country
		}
		if out[i].City != out[j].City {
			return out[i].City < out[j].City
		}
		return out[i].Hostname < out[j].Hostname
	})
	return out
}

// Parse decodes an API body. Used by tests and as a fallback parser.
func Parse(data []byte) ([]Relay, error) {
	var doc document
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	relays := Flatten(doc)
	if len(relays) == 0 {
		return nil, fmt.Errorf("relay list had no usable servers")
	}
	return relays, nil
}

// Filter keeps one country. An empty code keeps every relay.
func Filter(relays []Relay, country string) ([]Relay, error) {
	country = strings.ToLower(strings.TrimSpace(country))
	if country == "" {
		return relays, nil
	}
	if len(country) != 2 {
		return nil, fmt.Errorf("country must be a two-letter code")
	}
	var out []Relay
	for _, r := range relays {
		if r.CountryCode == country {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no WireGuard servers in %s", strings.ToUpper(country))
	}
	return out, nil
}

// Countries summarizes the list for the picker, sorted by name.
func Countries(relays []Relay) []Country {
	type acc struct {
		name   string
		cities map[string]struct{}
		relays int
	}
	order := []string{}
	by := map[string]*acc{}
	for _, r := range relays {
		a := by[r.CountryCode]
		if a == nil {
			a = &acc{name: r.Country, cities: map[string]struct{}{}}
			by[r.CountryCode] = a
			order = append(order, r.CountryCode)
		}
		a.cities[r.CityCode] = struct{}{}
		a.relays++
	}
	out := make([]Country, 0, len(order))
	for _, code := range order {
		a := by[code]
		out = append(out, Country{Name: a.name, Code: code, Cities: len(a.cities), Relays: a.relays})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ByHostname finds a relay.
func ByHostname(relays []Relay, host string) (Relay, bool) {
	host = strings.ToLower(strings.TrimSpace(host))
	for _, r := range relays {
		if r.Hostname == host {
			return r, true
		}
	}
	return Relay{}, false
}
