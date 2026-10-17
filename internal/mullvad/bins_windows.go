//go:build windows

package mullvad

func extraBins() []string {
	return []string{`C:\Program Files\Mullvad VPN\resources\mullvad.exe`}
}
