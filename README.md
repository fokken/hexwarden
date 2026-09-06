# Hexwarden

Hexwarden is a Python CLI for Android security assessment. It combines
ADB-based device and application evidence with Bluetooth testing,
passive network analysis, opt-in TCP/UDP service fuzzing, and integrations for
Drozer, MobSF and EMBA. Its **21 modules** cover system hardening, interfaces,
networking, wireless and running applications; every run saves raw evidence,
text and JSON reports, and an inventory of artifact hashes.

[Installation](#installation-linux) · [Usage](#usage) · [Reports](#reports-and-evidence) · [Module guides](#module-guides) · [All checks](docs/CHECKS.md) · [Coverage](docs/PLAN.md)

## Installation (Linux)

### 1. Install the core dependencies

You need **Python 3.10+**, a Python virtual environment, Git and ADB. The commands below use Ubuntu/Debian package names; on other Linux distributions, install their equivalents. Basic collection has no third-party Python runtime dependencies.

```sh
sudo apt update
sudo apt install git python3 python3-venv python3-pip adb android-sdk-platform-tools-common
python3 --version
adb version
```

If your distribution supplies Python older than 3.10, install a supported interpreter before creating the virtual environment. You can also obtain ADB from Google's [SDK Platform Tools](https://developer.android.com/tools/releases/platform-tools); make sure `adb` is on your `PATH`.

### 2. Install Hexwarden

```sh
git clone https://github.com/fokken/hexwarden.git
cd hexwarden
python3 -m venv .venv
source .venv/bin/activate
python3 -m pip install --upgrade pip
python3 -m pip install -e .
hexwarden --version
hexwarden list
```

If you already have the checkout, start from `cd hexwarden`. Reactivate `.venv` in each new terminal. The editable installation uses the code in your checkout; run Hexwarden as your normal user. You can also use `python3 -m hexwarden` from the project directory.

### 3. Connect the Android device

Enable **Developer options → USB debugging**, connect a USB data cable, unlock the device and accept its USB debugging authorization prompt. Confirm that ADB reports the device as `device`:

```sh
adb devices -l
```

If it says `unauthorized`, check the device's authorization prompt. For USB permission errors on Ubuntu, ensure the Android udev rules above are installed and your account belongs to `plugdev`:

```sh
sudo usermod -aG plugdev "$USER"
```

Log out and back in after changing group membership, then reconnect the device. See Android's [Linux device setup instructions](https://developer.android.com/studio/run/device) for details. Other distributions may use different USB-access rules.

### 4. Add optional capabilities

Install only the dependencies for the checks you plan to use:

| Capability | Python extra | Additional requirement |
|---|---|---|
| Decode manifests and correlate permissions | `apps` (Androguard) | `--extract-apks` |
| Verify APK signatures and flag unwanted signers | None | `--extract-apks`; host `apksigner` and Java; `--blocked-certs` for policy comparison |
| Inspect trusted certificates | None | Host `openssl` |
| Analyze captured traffic | None | Host `tshark`; device-side `tcpdump` and `timeout` for capture |
| Fuzz selected TCP/UDP services | None | Host `radamsa`; explicit target IP/port and seed file |
| BLE discovery and reads | `bluetooth` (Bleak) | Bluetooth adapter, BlueZ service and host D-Bus access |
| Classic Bluetooth discovery | None | BlueZ `sdptool` and a Bluetooth adapter |
| Upload selected APKs to MobSF | `mobsf` (Requests) | Prepared MobSF server, API key and a `mobsf-upload/` folder |
| Drozer agent-context tests | None | Drozer CLI and a reachable Android agent |
| Offline firmware analysis via EMBA | None | Prepared EMBA installation and a firmware image |

For all Python extras and the optional Ubuntu/Debian host tools:

```sh
python3 -m pip install -e '.[apps,mobsf,bluetooth]'
sudo apt install openssl apksigner tshark bluez radamsa
```

On Ubuntu, some optional packages require the Universe repository.

If your distribution does not provide a `radamsa` package, build it from the
upstream source:

```sh
sudo apt install build-essential git
git clone https://gitlab.com/akihe/radamsa.git
cd radamsa
make
sudo make install
cd ..
radamsa --version
```

The source installation and the distribution package provide the same `radamsa`
executable; use one method, then confirm it is available on `PATH`.

See the [module guides](#module-guides) for tool setup, device requirements and detailed examples.

## Usage

```sh
# First audit: select the serial shown by adb devices -l
hexwarden scan --serial DEVICE_SERIAL

# Select modules or categories
hexwarden scan --modules verified_boot encryption outdated_os
hexwarden scan --category networking --category interfaces

# Extract and analyze a selected app
hexwarden scan --extract-apks --package com.example.app

# Use existing device root access and capture 30 seconds of traffic
hexwarden scan --root --capture-seconds 30

# Discover Bluetooth services from the host
hexwarden scan --modules bluetooth --bt-mac AA:BB:CC:DD:EE:FF

hexwarden scan --help
```

By default, scans select all collection modules, user 0, 30-second command deadlines, 5,000 log lines and a 90-day patch-age threshold. APK extraction, traffic capture, host Bluetooth testing and Radamsa socket fuzzing are opt-in. Use `--max-apps` to cap package collection, `--patch-max-age` to change the patch policy and `--data-dir` to change the output directory. `--user` selects settings/AppOps and user certificate paths; installed package visibility is determined by ADB.

The banner goes to stderr; `--no-banner` suppresses it. The original `android-audit` command and `python3 -m android_audit` remain compatible aliases.

## Module guides

| Guide | Details |
|---|---|
| [Applications](docs/APPLICATIONS.md) | APK extraction, certificate blocklists, permission correlation and shared UIDs |
| [Networking](docs/NETWORKING.md) | Network inventory, timed PCAP capture and cleartext analysis |
| [Bluetooth](docs/BLUETOOTH.md) | Host setup, Classic/BLE discovery, reads, connection and bounded write-authorization tests |
| [Radamsa fuzzing](docs/RADAMSA_FUZZ.md) | Explicit TCP/UDP service fuzzing with durable timestamped payload journals |
| [All checks](docs/CHECKS.md) | Every module's collected data, automated checks, findings and limits |
| [Integrations](docs/INTEGRATIONS.md) | MobSF, Drozer and EMBA setup |
| [Coverage](docs/PLAN.md) | All modules, categories and remaining gaps |

## Reports and evidence

```text
data/<timestamp>-<run-id>/
  report.txt           Human-readable findings and coverage
  report.json          Structured report (schema version 2)
  audit.log            Execution log
  adb-devices.txt      ADB discovery output
  capabilities.json    Host/device capability discovery
  inventory.json       Artifact sizes and SHA-256 hashes
  evidence/            Raw output, decoded evidence and packet captures
  apks/                Extracted APKs and manifests, when enabled
  integrations/        External analyzer output, when enabled
```

Reports separate **collection**, **automated analysis** and **manual verification**. Findings include stable IDs, affected assets, evidence references, remediation and verification steps. **No findings does not mean secure.** Read the [report format and migration guide](docs/REPORT_FORMAT.md) for field definitions and automation guidance.

Preflight detects host tools, Android commands/services and requested root access. Known missing capabilities produce explicit skips; unknown capabilities are attempted. Successful command execution does not establish complete analysis.

Raw evidence can contain sensitive information. Run directories use owner-only POSIX permissions, but data is not encrypted and total disk usage is not capped. Automated text analysis is limited to 2 MiB per command; full output is retained. The hash inventory is unsigned. The default `data/` directory is Git-ignored.

Exit codes: `0` execution completed (possibly with findings or coverage gaps), `1` fatal/module error, `2` invalid arguments, `130` interruption.

## Scope and limitations

Hexwarden does not acquire root, install applications, invoke app components or reboot devices. `--root` uses an already-root ADB shell or existing `su`. Bluetooth pairing can create a persistent bond; Drozer write tests require explicit target directories and attempt probe cleanup. See the linked guides for these opt-in operations.

Hardware key attestation, OTA enforcement and app/backend integrity checks still need target-specific validation. Exported APIs and permissive filesystem metadata are review candidates; Drozer access tests establish behavior specifically in the agent's context. Bluetooth write probes are target-specific and opt-in; accepted writes still require controlled paired/unpaired validation. The [coverage plan](docs/PLAN.md) details each module's capabilities and gaps.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q android_audit hexwarden
```

Tests use simulated ADB and mocked Bluetooth/Drozer interfaces. Physical-device and live external-integration validation remain outstanding. See the [coverage plan](docs/PLAN.md) and [reporting developer notes](docs/REPORT_FORMAT.md#adding-checks) when adding modules or findings.
