# Mullvad Fastest

Find the fastest Mullvad WireGuard server and connect to it.

It downloads the live relay list, pings one server in each city, then pings every server in the cities that came back fastest. The window is one screen: pick a country or leave it on Anywhere, hit Find fastest, click Connect.

<video src="Cropped.mp4" width="1224" height="1080" autoplay loop muted playsinline controls></video>

## Run

You need the [Mullvad](https://mullvad.net) app installed for Connect, and for a true reading while a tunnel is already up. The scan itself only needs Go and a network.

```bat
build.bat
mullvad-fastest.exe
```

`build.bat` compiles a window without a console. From a terminal, a normal build works too:

```
go build -o mullvad-fastest.exe .
mullvad-fastest.exe scan
```

### Commands

```
mullvad-fastest                         open the window
mullvad-fastest scan                    fastest servers, anywhere
mullvad-fastest scan -country se        one country
mullvad-fastest scan -top 5 -json       machine-readable
mullvad-fastest connect se-sto-wg-001   switch to that server
mullvad-fastest disconnect
mullvad-fastest status
```

Closing the window stops the program. If you start it twice, the second launch opens the window that is already running.

## How a scan stays short

Mullvad publishes about 500 WireGuard relays across about 90 cities. Pinging all of them is wasted work once you know which cities are close.

1. Ping one relay in every city (or every relay, when the list is already small).
2. Keep the cities within 25ms or 25% of the best time, and at most five of them.
3. Ping every relay in those cities.

That whole pass usually finishes in about a second. A single country is faster, because a short list is pinged directly.

Pings run 48 at a time, straight to the relay IP, through Windows `IcmpSendEcho`. There is no DNS lookup and no `ping.exe` process per server. A relay that ignores ICMP is timed with a TCP handshake to port 443 instead. That number is connect time. It is marked `tcp` so it is not confused with a ping.

## Measuring while you are connected

A ping started inside the Mullvad tunnel does not measure your real path to the relay. On Windows, a scan temporarily adds this program to Mullvad split tunneling and turns split tunneling on if it was off. The probe runs in a new process, so its packets leave the tunnel. When the scan finishes, the previous split-tunnel setting is put back.

If the program is killed in the middle of a scan, run it once more. On startup it puts that setting back.

On Linux and macOS the tool still runs, using the system `ping` command. It does not change split tunneling there. Disconnect first if you want times that are not measured through the tunnel.

Connect uses the Mullvad CLI:

```
mullvad relay set location <hostname>
mullvad reconnect
```

## Build

Go 1.22 or newer.

```
go test ./...
go build -ldflags="-H windowsgui -s -w" -o mullvad-fastest.exe .
```

`-H windowsgui` is Windows-only. It hides the console when you double-click the exe. `mullvad-fastest.exe scan` from Command Prompt still prints, because the program attaches to that console.

## License

MIT. See [LICENSE](LICENSE).
