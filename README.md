<p align="center">
  <img src="assets/logo.png" alt="GoOffline" width="128" height="128">
</p>

<h1 align="center">GoOffline</h1>

<p align="center">
  <b>Make any Windows program think your internet is unplugged.</b><br>
  One switch. Just that program. Free and open source.
</p>

<p align="center">
  <a href="https://github.com/bjdevelopes/GoOffline/releases/latest"><img alt="Latest release" src="https://img.shields.io/github/v/release/bjdevelopes/GoOffline?color=FF5A6E&label=release"></a>
  <a href="https://github.com/bjdevelopes/GoOffline/blob/main/LICENSE"><img alt="MIT license" src="https://img.shields.io/badge/license-MIT-blue"></a>
  <img alt="Windows" src="https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078d6">
  <a href="https://buymeacoffee.com/bjdevelopes"><img alt="Buy Me a Coffee" src="https://img.shields.io/badge/☕%20Buy%20me%20a%20coffee-FFDD00?labelColor=FFDD00&color=FFDD00"></a>
</p>

<p align="center">
  <a href="https://bjdevelopes.github.io/GoOffline/"><b>Website</b></a> ·
  <a href="https://github.com/bjdevelopes/GoOffline/releases/latest"><b>Download</b></a> ·
  <a href="#how-it-works">How it works</a> ·
  <a href="CONTRIBUTING.md">Contributing</a>
</p>

---

## Download

Grab the latest `GoOffline-vX.Y.Z-win-x64.zip` from
[Releases](https://github.com/bjdevelopes/GoOffline/releases/latest), unzip it,
and run `GoOffline.exe`. You'll get one UAC prompt — that's for the firewall edits.

Windows 10 and Windows 11 only.

## How it works

### Tier 1 — Firewall (default)
Adds inbound + outbound block rules in Windows Firewall for the chosen `.exe`,
then resets its open IPv4 TCP connections so the cut is immediate. Flipping the
switch off deletes the rules. Rules show up as `GoOffline - ...` in Windows
Defender Firewall under the group **GoOffline**.

### Tier 2 — Hard mode (optional checkbox)
For programs that still get online. GoOffline injects a tiny hook DLL into the
running process and patches its import tables so every network call fails:

- `ws2_32`: `connect`, `WSAConnect`, `getaddrinfo`, `GetAddrInfoW`, `gethostbyname`, `WSAStartup`
- `wininet`: `InternetOpenA/W`, `InternetConnectA/W`
- `winhttp`: `WinHttpOpen`, `WinHttpConnect`
- `kernel32`: `LoadLibrary*` — so DLLs loaded later get patched too

Only takes effect while the target is running. New instances get hooked within
~2 seconds. **Won't work on anti-cheat games (Valorant, Fortnite, EAC, BattlEye) —
the kernel driver blocks remote DLL loads.** The firewall rule still catches those.

## Build from source

Requires .NET 8 SDK and (for Hard mode) VS C++ build tools.

```powershell
./native/GoOfflineHook/build.ps1
dotnet publish src/GoOffline -c Release -o publish
```

Full details in [CONTRIBUTING.md](CONTRIBUTING.md).

## Support the project

GoOffline is free and always will be. If it saved you time:

<p>
  <a href="https://buymeacoffee.com/bjdevelopes">
    <img alt="Buy Me a Coffee" src="https://img.buymeacoffee.com/button-api/?text=Buy%20me%20a%20coffee&emoji=☕&slug=bjdevelopes&button_colour=FFDD00&font_colour=000000&font_family=Inter&outline_colour=000000&coffee_colour=ffffff" />
  </a>
</p>

## License

[MIT](LICENSE).
