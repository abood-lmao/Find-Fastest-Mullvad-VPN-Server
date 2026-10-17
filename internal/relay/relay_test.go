package relay

import "testing"

func TestParseAndFilter(t *testing.T) {
	raw := []byte(`{
		"countries": [{
			"name": "Sweden",
			"code": "se",
			"cities": [{
				"name": "Stockholm",
				"code": "sto",
				"relays": [
					{"hostname": "se-sto-wg-001", "ipv4_addr_in": "1.2.3.4"},
					{"hostname": "", "ipv4_addr_in": "1.2.3.5"},
					{"hostname": "se-sto-wg-002", "ipv4_addr_in": "not-an-ip"}
				]
			}]
		}, {
			"name": "Germany",
			"code": "de",
			"cities": [{
				"name": "Berlin",
				"code": "ber",
				"relays": [{"hostname": "de-ber-wg-001", "ipv4_addr_in": "5.6.7.8"}]
			}]
		}]
	}`)
	relays, err := Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 2 {
		t.Fatalf("got %d relays", len(relays))
	}
	if relays[0].Hostname != "de-ber-wg-001" {
		t.Fatalf("sort: first is %s", relays[0].Hostname)
	}

	only, err := Filter(relays, "SE")
	if err != nil {
		t.Fatal(err)
	}
	if len(only) != 1 || only[0].City != "Stockholm" {
		t.Fatalf("filter: %+v", only)
	}
	if _, err := Filter(relays, "no"); err == nil {
		t.Fatal("expected missing country")
	}

	countries := Countries(relays)
	if len(countries) != 2 || countries[0].Name != "Germany" || countries[0].Relays != 1 {
		t.Fatalf("countries: %+v", countries)
	}
}
