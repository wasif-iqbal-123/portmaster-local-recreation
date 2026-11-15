# Portmaster-Local

A lightweight local recreation of Portmaster: it runs its own DNS resolver and
filter list engine, records connection events, and optionally configures the OS
(Windows Firewall rules, system DNS settings) for blocking.

## Layout

- `core/` — `portmaster-core` library (resolver, filters, rules, monitor, store, platform flags)
- `src-tauri/` — Tauri 2 desktop shell (`portmaster-local` binary)
- `ui/` — static dashboard served by Tauri
- `src-tauri/tauri.conf.json` — application and bundle configuration
- `src-tauri/tauri.windows.conf.json` / `tauri.linux.conf.json` — platform bundle targets

## Platform capabilities

| Capability | Windows | Linux | Android |
|---|---|---|---|
| DNS resolver (UDP/TCP) | implemented | implemented | core code only; no Android app wiring |
| Filter list updates | `ureq`/native-tls with bootstrap DNS | `curl` subprocess | only the portable core code; unverified |
| Connection monitor | Windows IP Helper | `/proc/net` | returns an empty list |
| System DNS apply/reset | PowerShell DnsClient cmdlets | `resolvectl` | not implemented |
| Packet (per-app) blocking | Windows Firewall | not implemented | not implemented |

The snapshot exposes `platform`, `firewall_supported`,
`system_dns_supported`, and `connection_monitor_supported`. The dashboard disables Windows-only controls on
platforms where the build cannot implement them, and labels the interface field
as a Windows index or a Linux name.

Linux and Android are DNS-filtering only in this version; nothing in the code
blocks packets at the firewall level there. Android has no VPN service or
tunnel integration, so other apps' DNS traffic is not intercepted by this app.

## Background/tray mode and one-time setup

- The GUI-subsystem build runs the DNS engine in the background. Closing the
  dashboard hides it to the system tray instead of quitting. On Windows, click
  the tray icon to reopen the dashboard; the tray menu has **Open dashboard**
  and **Quit Portmaster-Local**. On Linux, tray click events are unsupported by
  Tauri, so use the tray menu to reopen it.
- A manual launch opens the dashboard. A `--system-wide` or `--deploy` launch
  starts in the tray without showing the window. The login task uses
  `--system-wide`, so it starts silently in the background.
- Quitting from the tray restores the recorded system DNS and browser DoH
  policy. The elevated `--dns-guard` task watches the main process and restores
  the same state if the app crashes or is killed.
- Installation is one-time. The NSIS installer installs the app and registers
  an uninstaller once. Running `--deploy` once creates two persistent logon
  tasks (`Portmaster-Local System DNS` and `Portmaster-Local DNS Guard`). At
  login those tasks only start the already-installed exe; they do not reinstall
  the app or recreate the tasks.
- The app refuses to apply system DNS unless it owns UDP 53 and its upstream
  self-test succeeds. Upstream DoH and filter hostnames are bootstrapped using
  the prior recorded DNS servers, so the OS resolver cannot point back into the
  local resolver and loop.

## Building on Windows

Verified prerequisites on the development machine:

- Rust 1.99.1 with the `x86_64-pc-windows-msvc` toolchain
- Visual Studio Build Tools with the C++ workload and a Windows SDK
- WebView2 runtime (required by Tauri's WebView2 window)

```powershell
cargo test --workspace
cargo build -p portmaster-local --release
# target\release\portmaster-local.exe
```

The Windows Firewall and system DNS commands require administrator rights.
Binding DNS port 53 also requires administrator rights; without elevation set
`dns_port` to 5333 in Settings and use that port explicitly.

### Windows installers

```powershell
cargo install tauri-cli --version "^2.0.0"
cargo tauri build
# targets from tauri.windows.conf.json: .msi and -setup.exe (NSIS)
```

Tauri's bundler downloads the WiX and NSIS toolchains on first use, so the
first installer build needs network access. MSI generation additionally needs
the Windows VBSCRIPT/Windows Installer scripting engine. The NSIS installer was
verified (`cargo tauri build --bundles nsis`) and is configured for
`perMachine` installs, so it appears in Program Files with an uninstall entry.
Silent per-machine install was verified (`setup.exe /S`, exit 0). A verified
installer is kept at `../dist/Portmaster-Local_0.1.0_x64-setup.exe`. The MSI
build fails here at WiX ICE validation (`LGHT0217`); enabling the VBSCRIPT
optional feature and retrying on a machine with the Windows Installer scripting
engine is required for MSI.

The repository contains only the portable source tree plus the installer; build
outputs (`target/`), offline caches (`.cargo/`, `.tools/`), test artifacts, and
logs are excluded by `../.gitignore`. This is the handoff tree for the Windows,
Linux (CachyOS), and future Android builds.

## Building on Linux

Install the Tauri system dependencies, for example on Debian/Ubuntu:

```bash
sudo apt update
sudo apt install libwebkit2gtk-4.1-dev build-essential curl wget file \
  libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
```

Then:

```bash
cargo test -p portmaster-core
cargo build -p portmaster-local --release
cargo install tauri-cli --version "^2.0.0"
cargo tauri build   # targets: .deb and AppImage
```

The filter updater and DoH requests use `ureq`/native-tls on Linux, so `curl` is not
required for them. `resolvectl` (from systemd-resolved) is used for the optional
system DNS apply/reset; those calls need root. DNS port 53 needs root or
CAP_NET_BIND_SERVICE, otherwise use `dns_port = 5333`. The tray icon needs the
distro's `libayatana-appindicator` package.

An earlier Linux build and `deb`/AppImage bundles were verified in a Fedora 44
WSL environment before the T7 bootstrap/tray changes. The current tree still
needs a fresh CachyOS build/test with the tray/appindicator dependencies; the
Windows host has no Linux linker or GTK/webkit development libraries.

### CachyOS / Arch Linux

CachyOS is Arch-based and uses `pacman`, not `.deb`. You do not need a CachyOS
one-click package. Two supported routes:

**Run the AppImage**

```bash
sudo pacman -S --needed fuse2
chmod +x Portmaster-Local_0.1.0_amd64.AppImage
./Portmaster-Local_0.1.0_amd64.AppImage
```

If FUSE is unavailable, extract and run it instead:

```bash
./Portmaster-Local_0.1.0_amd64.AppImage --appimage-extract-and-run
```

The AppImage is self-contained, but AppImages built on a newer glibc can fail on
an older rolling release. If that happens, build locally rather than using the
prebuilt AppImage.

**Build natively**

```bash
sudo pacman -S --needed base-devel rust cargo gtk3 webkit2gtk-4.1 openssl librsvg libayatana-appindicator
cargo install tauri-cli --version "^2.0.0"
cargo tauri build --bundles appimage
```

This produces `target/release/bundle/appimage/Portmaster-Local_*.AppImage`.
The `.deb` package is for Debian/Ubuntu; on CachyOS use the AppImage or the
native build. `debtap` can convert the `.deb`, but that is not recommended for a
rolling Arch system.

## Building on Android

Tauri's Android target needs the Android SDK, NDK (side by side), SDK build
tools, command-line tools, and a JDK compatible with Android Studio's Gradle.
Set `ANDROID_HOME` and `NDK_HOME`, then:

```bash
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android
cargo install tauri-cli --version "^2.0.0"
cargo tauri android init   # generates the Android Studio project
cargo tauri android build --apk   # or --aab for Play Store
```

Android packaging is **not verified**: this machine has only the
`x86_64-pc-windows-msvc` Rust target installed, no Android SDK/NDK, and the
Tauri mobile project has not been initialized. It also needs an Android VPN or
tunnel design before it can filter other applications' DNS, which is outside
this app's current desktop-window architecture.

On Android, resolve the data directory explicitly with
`PORTMASTER_LOCAL_DATA_DIR` pointing at an app-private writable directory;
the desktop `APPDATA` and `HOME/.local/share` conventions are not reliable
there.

## CI

A GitHub Actions workflow is provided at
`../.github/workflows/portmaster-local-ci.yml` (repository root assumed to be
the workspace root). It runs:

- Windows: `cargo test --workspace` and a release build
- Linux: installs Tauri dependencies, tests the core crate, and builds
- Android: `cargo check -p portmaster-core --target aarch64-linux-android`
  (a core compile check only; APK builds need the SDK/NDK, which the workflow
  does not install)

## Verification status

Executed:

- Windows: `cargo test --workspace` — **83** tests passed in
  `portmaster-core` and 6 bridge-contract tests passed in
  `portmaster-local` (0 failed); the release build produced
  `target/release/portmaster-local.exe` (8,732,160 bytes).
- Windows NSIS installer: `cargo tauri build --bundles nsis` succeeded,
  producing a 2,157,961-byte per-machine installer. The installed copy is
  `C:\Program Files\Portmaster-Local\portmaster-local.exe`, and the installer
  carries the same verified build.
- Live verification (2026-11-14, elevated): system DNS applied to `127.0.0.1`;
  `example.com` resolved and HTTP returned 200; NSFW domain `rule34.xxx` was
  blocked by the local resolver. Forcing Windows DNS back to the router was
  automatically corrected by the DNS supervisor within roughly ten seconds,
  with filtering and internet still working. A hard kill restored
  `192.168.1.1`/`192.168.68.1` and internet in about five seconds; relaunching
  `--system-wide` re-applied DNS and blocking. Helper PowerShell/schtasks
  processes now use `CREATE_NO_WINDOW`, so the supervisor checks no longer pop
  visible console windows.
- The temporary PowerShell minute supervisor was removed; only the app and
  elevated DNS-guard scheduled tasks remain.
- Linux (Fedora 44/WSL): `cargo test -p portmaster-core` — 51 tests passed;
  `cargo build -p portmaster-local --release` succeeded; `cargo tauri build
  --bundles deb,appimage` produced a 2.91 MiB `.deb` and a 107.83 MiB AppImage.
  The AppImage runtime was exercised with `--appimage-extract` and extracted
  successfully. Artifacts are under `.tmp/linux-bundles/`.
- GUI runtime: a full-access launch on 2026-11-08 rendered the connected
  dashboard and passed the in-page IPC/command self-test (snapshot, settings,
  app rule, custom domain, DNS report, filter update). The check captured zero
  console errors and produced `.t4-verification/dashboard.png`. The first run
  exposed CSP violations; the config now allows `connect-src ipc:
  http://ipc.localhost` and inline style writes were replaced with CSS classes.
  The `PrintWindow` helper failed because `System.Drawing.Common` is unavailable,
  so the verified screenshot was captured through CDP.

Not verified / blocked:

- Windows MSI: `cargo tauri build --bundles msi` fails at WiX ICE validation
  (`LGHT0217`, Windows Installer scripting engine unavailable in this session).
  An older MSI file remains in the bundle directory but was not validated.
  Starting the `msiserver` service did not resolve the ICE failure. A machine
  with the Windows VBSCRIPT/Windows Installer scripting engine enabled should
  retry the MSI build.
- Android packaging: no Android SDK/NDK, no Android Rust target, and no Tauri
  mobile project were available. Only the CI core compile check is specified;
  APK generation remains unverified. Android also needs VPN/tunnel integration
  before it can filter other apps.
- Windows MSI and Android APK remain unverified; firewall rules and system DNS
  apply/revert have been exercised live with cleanup (T2/T7).

## Runtime notes

- `PORTMASTER_LOCAL_DATA_DIR` overrides the per-user data directory.
- `PORTMASTER_LOCAL_APP_DIR` overrides the Tauri app data directory (used for WebView2 data).
- The engine binds `127.0.0.1:53` by default; change `dns_port` if the port is
  occupied or privileges are unavailable.
- Applying or reverting system DNS changes the machine's resolver settings;
  use the reset action or `resolvectl revert` to restore them.
- Filter lists are fetched from public URLs with `ureq`/native-tls; updates require
  network access and are skipped when offline.
- Upstream filter hostnames are resolved through the DNS servers recorded
  before `--deploy` points the OS at this app. Queries first use plain DNS to
  those recorded servers for fast Windows DNS responses; DoH is the fallback.
- The DNS supervisor checks the active interface and re-applies local DNS if
  Windows/DHCP resets it. It only re-applies after an upstream self-test, and if
  the upstream becomes unhealthy while local DNS is active it restores the
  recorded pre-deployment DNS so internet is not broken.
- Do not run `--deploy` at login. It is intended as a one-time elevated setup
  step; at login the tasks run only `--system-wide` and `--dns-guard`.
