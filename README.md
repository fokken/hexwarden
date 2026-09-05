# Hexwarden

Fantasy-inspired name, evidence-driven auditing. Hexwarden is a modular Python CLI for collecting and reviewing Android security evidence over ADB. Includes **20 audit modules** grouped into system hardening, interfaces, networking, wireless and running applications. See [the design and coverage plan](docs/PLAN.md) for exactly what each module can establish.

Requires Python 3.10+ and an authorized ADB connection. The standard-library collectors run directly from this directory:

```sh
python3 -m hexwarden list
python3 -m hexwarden scan --serial DEVICE_SERIAL
```

Or install the CLI and optional APK/MobSF dependencies:

```sh
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[apps,mobsf]'
hexwarden scan --serial DEVICE_SERIAL --extract-apks
```

Install Android SDK `apksigner` on the host for APK signature verification, `openssl` for CA inspection, and `tshark` for PCAP analysis. Passive capture requires device-side `tcpdump` and `timeout`; the tool does not install them. Optional dependencies are not needed for basic collection.

The CLI displays a rune-inspired ASCII banner on stderr, keeping stdout available for command output. Use `--no-banner` before or after the subcommand to suppress it; `hexwarden --version` prints just the version. `python3 -m hexwarden` works directly from the source checkout. The original `android-audit` entry point and `python3 -m android_audit` remain available for existing scripts.

## Select scope

```sh
# Run individual modules
python3 -m hexwarden scan --modules verified_boot encryption outdated_os

# Run one or more categories
python3 -m hexwarden scan --category networking --category interfaces

# Use existing root access for privileged reads and capture 30 seconds
python3 -m hexwarden scan --root --capture-seconds 30

# Pull and analyze selected apps, including installed split APKs
python3 -m hexwarden scan --extract-apks \
  --package com.example.app --package com.example.service

# Bound bulk work and set patch-age policy
python3 -m hexwarden scan --extract-apks --max-apps 100 --patch-max-age 120
```

Default: all modules, all visible packages, user 0, 30-second command deadlines, 5,000 log lines and a 90-day patch-age policy. APK pulling and passive capture are opt-in. `--user` applies to settings/AppOps and user CA paths; the installed package inventory is device-wide as exposed by ADB. `--max-apps` prioritizes `/priv-app/` packages. `--data-dir` changes the output parent directory.

No root acquisition, application installation, component invocation, Bluetooth writes or reboot are performed. `--root` uses an already-root ADB shell or existing `su -c` for collectors requiring it; it never runs `adb root`. Collection still consumes device CPU/I/O and may appear in device logs. Host Bluetooth tests are opt-in; `--bt-pair` can create a persistent Bluetooth bond. Drozer write probes require explicit `--drozer-write-dir` targets.

## Capability discovery

Every scan performs preflight discovery and saves `capabilities.json` plus raw evidence under `evidence/capabilities/`. This records host executable paths, optional Python dependency versions, Android SDK/release, shell UID, device commands in PATH, the visible Binder service inventory, and existing root availability when requested.

Collectors skip commands/services known to be unavailable and record each reason in `skipped_checks`. Unknown capabilities are still attempted. Root-only reads are skipped if the requested root context cannot be established; an already-root ADB shell does not require `su`. Network collection falls back from `ss` to `netstat` when available. Root command discovery uses the root PATH separately from the ADB shell PATH.

Presence is not proof of supported command options or sufficient permissions. Checks still retain execution errors, and capabilities can change during a run. Preflight is separate from the 20 audit modules and is embedded in the JSON report.

## Bluetooth testing from the host

Supply the remote device's MAC to enable host-side testing in addition to the ADB Bluetooth inventory:

```sh
pip install -e '.[bluetooth]'
python3 -m hexwarden scan --serial DEVICE_SERIAL --modules bluetooth \
  --bt-mac AA:BB:CC:DD:EE:FF

# Attempt BLE characteristic reads and Classic endpoint connections
python3 -m hexwarden scan --modules bluetooth \
  --bt-mac AA:BB:CC:DD:EE:FF --bt-read --bt-connect-classic

# BLE-only assessment with explicit pairing (may prompt on the device/host)
python3 -m hexwarden scan --modules bluetooth \
  --bt-mac AA:BB:CC:DD:EE:FF --bt-mode ble --bt-pair --bt-read --bt-timeout 60
```

The host's **default Bluetooth adapter** must be powered and usable by the current user. Linux supports both transports; Classic discovery requires BlueZ `sdptool` (some distributions package it with deprecated BlueZ tools). BLE uses [Bleak](https://bleak.readthedocs.io/en/latest/api/client.html) and supports MAC targeting on Linux/Windows. macOS MAC targeting is not supported. No tools are automatically installed or adapters powered on. ADB is still required by the main scan command. `--root` affects device-side ADB reads, not host Bluetooth permissions.

* `--bt-mode both|classic|ble` selects transports; default `both`.
* Classic SDP discovery saves service records, advertised RFCOMM channels and L2CAP PSMs, using [BlueZ sdptool](https://github.com/bluez/bluez/blob/master/tools/sdptool.c).
* BLE connects and saves service/characteristic UUIDs, handles, descriptors and advertised properties. Write-capable characteristics become informational review candidates; no writes are attempted.
* `--bt-read` attempts characteristics advertising read support and records successes/failures. Values are retained as hex in raw evidence and excluded from finding text. No descriptor reads or notification subscriptions are performed.
* `--bt-connect-classic` connects and immediately closes up to 32 unique SDP-advertised RFCOMM/L2CAP endpoints, with a maximum five-second timeout each. No application payload is sent. This is not a channel sweep.
* `--bt-pair` explicitly requests pairing through Bleak. Pairing can prompt and persist; the tool does not unpair afterward. Existing bonds are used even without this flag, and OS security handling may prompt during connections/reads.
* `--bt-timeout` bounds each discovery phase (default 30 seconds); the BLE budget includes discovery, connection, pairing, enumeration and reads. Individual reads have a five-second maximum within that budget. Increase it for interactive pairing or many characteristics.

All host command output and structured BLE results are stored under `evidence/bluetooth/`, alongside `sdp-services.json` and available before/after `bluetoothctl` host-state snapshots. Missing tools, absent targets, denied reads and timeouts produce coverage limitations.

Successful reads/connections reflect the **current host security context**, not proof of unauthenticated access or a vulnerability. GATT properties do not establish effective write authorization. The supplied MAC is not independently tied to the ADB target; BLE private addresses can change or differ from the Classic address. SDP may omit non-browsable services. Connection attempts and reads can trigger device behavior; actual write testing needs a device-specific payload and remains unimplemented.

## Reports and evidence

Each run creates:

```text
data/<UTC-timestamp>-<run-id>/
  report.json          # structured findings, coverage and command provenance
  report.txt           # human-readable findings and coverage
  audit.log            # execution log
  adb-devices.txt      # discovery evidence
  capabilities.json   # host/device preflight and evidence references
  inventory.json      # SHA-256 and size of each saved artifact
  evidence/<module>/   # raw stdout/stderr, decoded/derived evidence, PCAP
  apks/<package>/      # APKs and decoded manifests when enabled
  integrations/        # optional external analyzer reports
```

Each module has `collected`, `partial`, `skipped`, or `error` coverage status. These are **not security pass/fail verdicts**. Findings include severity, confidence and evidence references. Command records include arguments, return code, timeout and stderr path. Absent settings, unavailable services and denied reads become limitations. Automated text analysis is capped at 2 MiB per command; complete raw output is retained.

Run directories use owner-only permissions on POSIX. Raw logs, certificates, packet captures and external reports can contain sensitive information; secret matches are omitted from finding text, but raw evidence is deliberately preserved. Data is not encrypted at rest. Captures are time-bounded, but total evidence/APK disk usage is not capped. Hashes detect later changes only when compared with a separately protected inventory; the inventory is not signed.

Exit codes: `0` completed execution (including partial/skipped coverage and security findings), `1` fatal/module error, `2` invalid arguments, `130` interruption. Automation must inspect report coverage and findings rather than treating exit 0 as secure.

## Optional integrations

**MobSF:** configure a prepared server and set `MOBSF_API_KEY` in your environment. Selecting `--mobsf-url` explicitly enables upload of the extracted APKs. Loopback HTTP is supported; remote servers require HTTPS. Credentials are not placed in command logs. The adapter uploads each APK, requests a static scan, then saves the JSON report using [MobSF's API](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/views/api/api_static_analysis.py).

```sh
python3 -m hexwarden scan --extract-apks \
  --mobsf-url http://127.0.0.1:8000 --package com.example.app
```

A queued/asynchronous MobSF deployment may not have a report ready immediately; this is reported as incomplete rather than silently accepted. External results are retained as separate JSON evidence, not normalized into native findings.

**Drozer:** requires a running, reachable agent and installed host CLI. All interaction is through `drozer console connect`; Hexwarden does not import Drozer into its process or connect directly to its protocol. Prepare the connection yourself and verify that the agent is on the ADB-selected device. See the [Drozer project](https://github.com/ReversecLabs/drozer).

```sh
python3 -m hexwarden scan --drozer --drozer-server 127.0.0.1 \
  --package com.example.app \
  --drozer-list-path /data/user/0/com.example.app \
  --drozer-read-path /data/user/0/com.example.app/files/config.json

# Explicitly test file creation and writing in a selected directory
python3 -m hexwarden scan --drozer --package com.example.app \
  --drozer-write-dir /data/local/tmp
```

The integration discovers available modules using the CLI's `list` command. It runs built-in `app.package.list`, and for selected packages, `app.package.info`, `app.package.attacksurface`, `app.activity.info`, `app.service.info`, `app.provider.info` and `app.broadcast.info`. Missing modules are skipped with a coverage reason. `--max-apps` also caps the explicitly selected Drozer packages.

The bundled `hexwarden.audit` module is likewise invoked through the CLI. A per-run `.drozer_config` and module repository under `integrations/drozer/` load it without changing your home configuration or installing an APK. Its checks are:

* Agent package, UID, PID, Android user, package GIDs and SELinux context where accessible.
* Effective `PackageManager.checkPermission` results for requested permissions of the agent and selected packages. Built-in package-info output alone is not treated as granted permissions.
* Directory-listing attempts against `--drozer-list-path` targets (default `/data`, `/data/local/tmp`, `/sdcard`). There is no recursive scan. Up to `--drozer-entry-limit` names are retained per directory, default 50, maximum 1,000; Android's directory-list API still enumerates the directory internally.
* A one-byte read attempt against each `--drozer-read-path` regular file, with the byte discarded. Empty files can still demonstrate successful opening. No special devices or FIFOs are opened.
* Optional `--drozer-write-dir` tests using Java-created unique `hexwarden-*.probe` files. Each probe writes one byte and attempts deletion in a cleanup block. Probe creation is logged immediately; an unconfirmed cleanup is reported. Forced termination can leave a probe behind.

Actual probe outcomes and agent identity are saved in `agent-checks.json` and included in findings. Access successes are informational observations, not automatically vulnerabilities. ADB separately collects package AppOps, accessibility/notification-listener settings and device policy. Package grants alone do not prove AppOps authorization or successful use of a privileged API. The agent's Android user may differ from `--user`; that mismatch is reported.

Use `--drozer-bin /path/to/drozer` for a custom CLI. The per-run configuration is isolated from your home Drozer configuration. This adapter uses a prepared endpoint that can connect noninteractively without an agent password; `--no-password` and `--no-color` are selected if supported by CLI help. Password-protected/interactive TLS setups need additional adapter support and may fail with a recorded coverage gap. No automatic forwarding or privileged execution occurs.

The bundled helper targets the current Reversec agent permission namespace. CLI/module APIs were inspected against [Drozer source revision d992f63](https://github.com/ReversecLabs/drozer/tree/d992f6378d42680ea96ee03eff4117f150e1049c). Older agents can expose different capabilities; an unavailable helper is reported rather than replaced with weaker permission-bit evidence.

**EMBA:** provide an already obtained firmware image or extracted directory and a prepared installation. EMBA's dependencies and execution environment are managed separately; no firmware partition dumping occurs. See [EMBA](https://github.com/e-m-b-a/emba).

```sh
python3 -m hexwarden scan --emba /opt/emba/emba \
  --emba-firmware /path/to/firmware.bin --integration-timeout 7200
```

## Interpretation and limitations

ADB cannot conclusively prove every requested security property. Host Bluetooth tests add discovery and read/connection checks, but actual write authorization still needs device-specific validation. Hardware-backed keys need per-key attestation; OTA enforcement needs update/firmware review; Play Integrity enforcement needs app/backend review. Exported APIs and world-writable files are candidates until runtime checks and SELinux policy are considered. Android Auto/vendor projection roles require OEM-specific evidence. The report explicitly records these limitations.

Implementation references include Android's [exported-component guidance](https://developer.android.com/privacy-and-security/risks/android-exported), [Android 12 backup behavior](https://developer.android.com/about/versions/12/behavior-changes-12), and [AVB documentation](https://android.googlesource.com/platform/external/avb/+/master/README.md). In particular, backup-manager enablement is not reported as proof that ADB backups are possible.

## Development

```sh
python3 -m unittest discover -s tests -v
python3 -m compileall -q android_audit
```

Add a module exposing `CATEGORY` and `run(context)`, then register its name in `android_audit/modules/__init__.py`. Use context collection methods to preserve evidence and coverage. Avoid treating missing output as a passing check.

The included tests use a simulated ADB device, mocked host Bluetooth scanners/clients/sockets, and mocked Drozer CLI/reflection interfaces. Capability tests distinguish absent from unknown tools, verify service skips, and check both root-shell and unavailable-root behavior. Real-device/OEM testing, physical Bluetooth testing and live MobSF/Drozer/EMBA validation have not been performed in this workspace.
