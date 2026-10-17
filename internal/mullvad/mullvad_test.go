package mullvad

import "testing"

func TestParseStatus(t *testing.T) {
	out := "Connected\r\n    Relay:                  fr-mrs-wg-001\r\n    Features:               Quantum Resistance\r\n    Visible location:       France, Marseille. IPv4: 138.199.15.173\r\n"
	st := parseStatus(out)
	if st.State != "Connected" || st.Relay != "fr-mrs-wg-001" || st.Location != "France, Marseille" {
		t.Fatalf("%+v", st)
	}
	empty := parseStatus("Disconnected\n")
	if empty.State != "Disconnected" || empty.Relay != "" {
		t.Fatalf("%+v", empty)
	}
}

func TestParseSplit(t *testing.T) {
	on, apps := parseSplit("Split tunneling state: off\nExcluded applications:\n")
	if on || len(apps) != 0 {
		t.Fatalf("off: %v %v", on, apps)
	}
	on, apps = parseSplit("Split tunneling state: on\nExcluded applications:\nC:\\Windows\\System32\\PING.EXE\n")
	if !on || len(apps) != 1 || apps[0] != `C:\Windows\System32\PING.EXE` {
		t.Fatalf("on: %v %v", on, apps)
	}
}
