# Hexwarden

**Inspect the runes. Expose the cracks.**

Hexwarden is a Python CLI for auditing Android devices over ADB. Its **20 modules** cover system hardening, interfaces, networking, wireless and running applications. Each run saves raw evidence, text and JSON reports, and an inventory of artifact hashes.

[Installation](#installation-linux) · [Usage](#usage) · [Reports](#reports-and-evidence) · [Coverage](docs/PLAN.md) · [Bluetooth](docs/BLUETOOTH.md) · [Integrations](docs/INTEGRATIONS.md)

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
| Verify APK signatures and approved signers | None | `--extract-apks`; host `apksigner` and Java; `--approved-certs` for policy comparison |
| Inspect trusted certificates | None | Host `openssl` |
| Analyze captured traffic | None | Host `tshark`; device-side `tcpdump` and `timeout` for capture |
| BLE discovery and reads | `bluetooth` (Bleak) | Bluetooth adapter, BlueZ service and host D-Bus access |
| Classic Bluetooth discovery | None | BlueZ `sdptool` and a Bluetooth adapter |
| Submit APKs to MobSF | `mobsf` (Requests) | Prepared MobSF server and API key |
| Drozer agent-context tests | None | Drozer CLI and a reachable Android agent |
| Offline firmware analysis via EMBA | None | Prepared EMBA installation and a firmware image |

For all Python extras and the optional Ubuntu/Debian host tools:

```sh
python3 -m pip install -e '.[apps,mobsf,bluetooth]'
sudo apt install openssl apksigner tshark bluez
```

The distribution's [`apksigner` package](https://packages.ubuntu.com/noble/apksigner) installs its Java dependency. If using Android SDK Build Tools instead, expose its `apksigner` executable on `PATH`. On Ubuntu, some packages require the Universe repository. `tshark` only reads saved PCAPs here; it does not need host live-capture privileges.

For Bluetooth testing on a Linux host using systemd:

```sh
sudo systemctl start bluetooth
bluetoothctl show
bluetoothctl power on
command -v sdptool
```

Ubuntu's [`bluez` package includes `sdptool`](https://packages.ubuntu.com/noble/amd64/bluez/filelist); other distributions may package it separately as a deprecated BlueZ tool. Hexwarden uses the default adapter and does not power it on automatically.

Installing `tcpdump` on the computer does **not** install it on Android. Device capture needs a compatible device-side binary and permissions, usually existing root access. Hexwarden does not install device tools or acquire root. See the [Bluetooth guide](docs/BLUETOOTH.md) and [MobSF, Drozer and EMBA setup](docs/INTEGRATIONS.md) for feature-specific requirements.

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

The network module collects interface addresses, link state, IPv4/IPv6 routes and policy rules, socket listeners, process identities and package UIDs. When `ss` exposes PIDs, listener records are correlated with `ps` and `pm list packages -U`; a `netstat` fallback is retained when `ss` is unavailable but cannot provide the same attribution. It also summarizes firewall chain policies and records default routes, interface roles and forwarding state. A wildcard bind remains a review candidate until its owning process, routes, firewall and reachable interfaces are checked together.

Passive analysis is opt-in with `--capture-seconds`. The complete capture is retained as `traffic.pcap` together with `capture-metadata.json`, even when `timeout` returns its normal stop code. Use `--capture-interface wlan0` to limit capture to one interface and `--capture-snaplen 256` to limit packet bytes; the default snap length `0` keeps full packets for manual review. The capture is then passed to `tshark`, which looks for application payloads in common cleartext protocols including HTTP, FTP, Telnet, SMTP, POP, IMAP, IRC, LDAP, MQTT, XMPP, SIP and RTSP. Findings retain protocol names and frame numbers but omit packet Info fields and payload contents, which may contain secrets. STARTTLS, QUIC, proprietary protocols and encrypted traffic still require manual review.

By default, scans select all modules, user 0, 30-second command deadlines, 5,000 log lines and a 90-day patch-age threshold. APK extraction, traffic capture and host Bluetooth testing are opt-in. Use `--max-apps` to cap package collection, `--patch-max-age` to change the patch policy and `--data-dir` to change the output directory. `--user` selects settings/AppOps and user certificate paths; installed package visibility is determined by ADB.

The banner goes to stderr; `--no-banner` suppresses it. The original `android-audit` command and `python3 -m android_audit` remain compatible aliases.

## Application trust and permission correlation

Use MobSF for broad APK analysis (`--mobsf-url`). Hexwarden correlates installed-app permissions and checks verified signers against your approved certificate policy:

```sh
hexwarden scan --modules app_extraction custom_permissions --extract-apks \
  --approved-certs approved-certs.json --package com.example.app
```

Save the following as `approved-certs.json` before running the command. The policy has a default allowlist and optional exact-package overrides. Replace the example fingerprint with an independently approved **certificate SHA-256** fingerprint (not the APK hash or public-key hash):

```json
{
  "default": [],
  "packages": {
    "com.example.app": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"]
  }
}
```

Overrides replace the default list. Empty lists approve no signers; every reported signer on every extracted base/split APK must be allowed. Fingerprints accept upper/lowercase hexadecimal and optional colon separators. Missing tools, failed verification and unrecognized output are **not evaluated**, never approved. Use the distribution package or Android SDK Build Tools described above and put `apksigner` on PATH; certificate comparison does not require Androguard. Signing-key rotation and device-specific signer selection still need review. The normalized policy and per-APK results are saved under `evidence/app_extraction/` as `approved-certs.json` and `signer-policy.json`. Verification uses Android's [apksigner](https://developer.android.com/tools/apksigner).

`--approved-certs` requires `--extract-apks` and selection of `app_extraction`. Without a policy, signature output is still collected when `apksigner` is available, but signer approval is not evaluated. The policy applies only to collected APKs; it does not require listed packages to be installed or prove that every split was extracted.

`custom_permissions` requires the `apps` extra and saves `permission-correlation.json`: declaring apps, requesting apps (including SDK conditions), and guarded components, including provider read/write and path permissions. It flags weak permissions guarding enabled exported components and multiple declaring packages. Missing declarations are scoped inventory gaps, not vulnerabilities. Run without `--package` for wider correlation. Requests are not grants; split merging, runtime checks and effective ownership require validation. See Android's [custom permission documentation](https://developer.android.com/guide/topics/permissions/defining).

With `--drozer`, the existing CLI-driven agent probe also records full package UIDs and visible same-UID peers in `evidence/drozer/shared-uids.json`. System-range UIDs, privileged installation paths and observed sensitive grants prioritize review. Android users remain separate. `--package` restricts starting packages while including their visible UID peers; without it, UID inventory covers apps visible to the agent. Grant probes still follow the existing selected-package scope. These are [PackageManager identities](https://developer.android.com/reference/android/content/pm/PackageManager), not proof that an app is currently running or has root access. Raw agent evidence, findings and coverage gaps remain available in the text/JSON reports.

Add `--drozer` after preparing the [Drozer integration](docs/INTEGRATIONS.md#drozer). `--max-apps` caps UID starting-package inspection as well as APK collection; same-UID peers can exceed that cap. Broader permission correlation benefits from omitting `--package`, but update the certificate policy for that wider scope first.

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

Bluetooth write authorization, hardware key attestation, OTA enforcement and app/backend integrity checks still need target-specific validation. Exported APIs and permissive filesystem metadata are review candidates; Drozer access tests establish behavior specifically in the agent's context. The [coverage plan](docs/PLAN.md) details each module's capabilities and gaps.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q android_audit hexwarden
```

Tests use simulated ADB and mocked Bluetooth/Drozer interfaces. Physical-device and live external-integration validation remain outstanding. See the [coverage plan](docs/PLAN.md) and [reporting developer notes](docs/REPORT_FORMAT.md#adding-checks) when adding modules or findings.
