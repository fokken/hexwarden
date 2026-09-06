# Checks and collected information

[Back to README](../README.md) · [Coverage plan](PLAN.md) · [Report format](REPORT_FORMAT.md)

This is the inventory of Hexwarden's built-in collection and analysis. A successful command means that evidence was collected; it does not mean that the device passed the check. Every run records raw command output, analysis checks, findings, limitations and manual-verification guidance under its run directory.

## System hardening

| Module | Collected information | Automated checks and findings | Limits |
|---|---|---|---|
| `developer_options` | Global developer settings, ADB debugging settings, wireless debugging settings, ADB TCP properties and `ro.adb.secure` | Valid setting/property values; `HW-DEV-001` for enabled development settings; `HW-DEV-002` for a configured network ADB port | A configured port does not prove that ADB is listening, reachable or authenticated |
| `screen_lock` | `dumpsys trust`, `dumpsys device_policy`, `dumpsys fingerprint`, `dumpsys face`, and lock-screen timeout setting | Records collection coverage; manual review of lock method, timeout, trust agents and enrolled biometrics | PIN/pattern strength, enrollment quality and OEM policy require device review; credential hashes are not collected |
| `encryption` | Crypto state/type properties and `sm list-volumes all` | `HW-ENC-001` when `ro.crypto.state` reports `unencrypted`; validates readable encryption properties | Does not prove per-volume key protection or hardware-backed credential-encryption keys |
| `unknown_sources` | Legacy unknown-source setting and `REQUEST_INSTALL_PACKAGES` AppOps query for the selected Android user | `HW-INSTALL-001` for enabled legacy unknown sources; `HW-INSTALL-002` when installer AppOps results require review | AppOps and OEM/device-management policy do not prove silent installation |
| `outdated_os` | System and vendor security-patch properties | `HW-PATCH-001` when patch age exceeds `--patch-max-age`; invalid, missing and future dates are coverage conditions | No CVE completeness, vendor-support or exploitability claim |
| `backup` | Backup manager enabled state, `bmgr enabled`, `dumpsys backup`, and backup setting | Records backup configuration for review | Does not initiate or prove ADB backup eligibility; Android version, target SDK, `allowBackup`, debuggability and OEM policy matter |
| `certificates` | System, Conscrypt and user certificate-store listings; certificate bytes when accessible; OpenSSL metadata and fingerprints; device certificate policy | `HW-CA-001` for certificate subject-name test/debug heuristics | Names are not proof of a test CA; compare fingerprints with an approved baseline and account for per-app trust configuration |
| `filesystem_acls` | SELinux mode, permissions/labels for selected system directories, bounded world-writable search, mounts | `HW-FS-001` for non-enforcing SELinux; `HW-FS-002` for bounded world-writable candidates | DAC metadata does not establish an ordinary app's access; SELinux, ACLs, namespaces and scoped storage require context testing |
| `secrets_trust` | Binder/HAL service lists, `lshal`, `dumpsys keystore2`, TEE/TPM/Trusty device nodes, candidate key and secret filenames | Records candidate secret paths without reading private-key contents | Service/device presence does not prove hardware-backed keys, attestation or correct key policy |
| `verified_boot` | Verified-boot state, flash-lock state, vbmeta device state, dm-verity mode and build tags | `HW-BOOT-001` unlocked bootloader; `HW-BOOT-002` boot-state review; `HW-BOOT-003` verity review; `HW-BOOT-004` test-key build tag | Runtime properties are not independent attestation and do not prove the trusted AVB key or rollback state |
| `updates_integrity` | A/B and virtual-A/B properties, slot data, update-engine/system-update dumps and OTA certificate metadata | Records update and OTA evidence | Does not verify OTA signatures, rollback enforcement, update endpoints or Play Integrity behavior |

## Interfaces and networking

| Module | Collected information | Automated checks and findings | Limits |
|---|---|---|---|
| `usb` | USB function state, USB sysfs device/interface IDs, vendor/product/class fields, input devices and block partitions | Records HID, storage, communications, CDC and wireless-controller classes | No physical acceptance test or HID-injection test is performed |
| `network` | IPv4/IPv6 addresses and links; routes and policy rules; TCP/UDP/Unix listeners; process and package UID mapping; connectivity, Wi-Fi, tethering and Ethernet dumps; forwarding flags; iptables/ip6tables rules; nftables tables/chains/hooks/policies/verdicts; network namespaces; eBPF network/program inventory | Interface, route, process, package-UID, listener and enforcement-context checks; `HW-NET-001` wildcard listeners; `HW-NET-002` forwarding; `HW-NET-004` permissive observed firewall policies | Root is needed for firewall/eBPF evidence; namespace, offload, OEM and eBPF behavior may remain invisible; listening does not prove remote reachability |
| `passive_network` | Opt-in PCAP from the selected device interface for `--capture-seconds`, interface and snap length metadata, and retained capture hashes | PCAP validity and `tshark` cleartext-protocol heuristics; `HW-NET-003` protocol candidates | No decryption; encrypted traffic, STARTTLS, QUIC and proprietary protocols require review; captures may contain sensitive data |

## Wireless

| Module | Collected information | Automated checks and findings | Limits |
|---|---|---|---|
| `bluetooth` | Android Bluetooth manager/service/sysfs inventory; optional host adapter state, Classic SDP services, RFCOMM/L2CAP endpoints, BLE services/characteristics/descriptors/properties, explicit write-probe metadata and payload journal | `HW-BT-001` advertised Classic services; `HW-BT-002` successful Classic endpoint connections; `HW-BT-003` advertised BLE write support; `HW-BT-004` readable BLE characteristics; `HW-BT-005` accepted explicit BLE write probe | Host MAC is user-supplied and not tied to ADB; existing bonds affect results; writes/fuzzing are opt-in, target-scoped and bounded; no notifications or application protocol payloads are sent |

## Running applications

| Module | Collected information | Automated checks and findings | Limits |
|---|---|---|---|
| `app_extraction` | Installed package paths, base/split APKs, SHA-256 hashes, decoded manifests, application attributes and `apksigner --print-certs` output | `HW-APP-004` debuggable applications; optional certificate blocklist status through `--blocked-certs` | Visible installed APKs only; private data, uninstalled firmware apps, signer rotation and device-specific selection require review |
| `app_apis` | Activities, aliases, services, receivers and providers; exported/enabled state; inherited permissions; provider read/write and path-permission metadata | `HW-APP-001` exported enabled components without manifest permission guards, subject to package-prefix filtering | Static manifest candidates only; merged split manifests, resources, per-user overrides and runtime authorization require validation |
| `privileged_apis` | Privileged-app candidates inferred from install paths and package flags, plus decoded service/provider components | `HW-APP-002` exported enabled service/provider candidates without guards, subject to package-prefix filtering | Privileged status is an inference; it does not prove sensitive operations or exploitable authorization |
| `custom_permissions` | Permission declarations, protection levels, requesting apps, SDK conditions, guarded components and provider path guards | `HW-APP-003` weak custom permission candidates, subject to package-prefix filtering; `permission-correlation.json` also records relationships and can produce `HW-APP-010` | Requests are not grants; effective ownership, signature exceptions, AppOps, runtime checks and split merging require validation |
| `logging_secrets` | Bounded `logcat` snapshot selected by `--log-lines` | Credential/private-key marker heuristics; `HW-LOG-001` with matched values omitted from findings | Heuristic false positives and misses are possible; raw log evidence may contain secrets |

The default package-prefix filter for `HW-APP-001`, `HW-APP-002` and `HW-APP-003` excludes names beginning with `com.google` and `com.android`. Add prefixes with `--privileged-api-exclude-prefix`; use `--privileged-api-no-default-excludes` to include those platform namespaces. Excluded packages are a coverage decision and are recorded in module limitations.

## Drozer integration

With `--drozer`, Hexwarden uses the Drozer CLI and a prepared agent. It discovers available modules, then runs global package/component inventory without package arguments:

- `app.package.list`, `app.package.info`, `app.package.shareduid`
- `app.activity.info`, `app.service.info`, `app.provider.info`, `app.broadcast.info`

The bundled `hexwarden.audit` agent module collects the agent package, UID, PID, Android user, package GIDs and SELinux context; effective `PackageManager.checkPermission` results; package UIDs and visible same-UID peers; bounded directory listings; one-byte read probes; and optional write probes with cleanup. The optional `--drozer-readable-path` invokes `scanner.misc.readablefiles` for selected directories. Path-shaped results produce `HW-DZ-005`; successful bounded access produces `HW-DZ-002`; unconfirmed write cleanup produces `HW-DZ-003`; sensitive granted permissions produce `HW-DZ-001`; shared/system UID groups produce `HW-DZ-004`.

Drozer evidence is agent-context evidence. It does not prove root, live-process identity, universal app access or confidentiality impact. See [INTEGRATIONS.md](INTEGRATIONS.md#drozer) for options and limits.

## Optional external analysis

`--mobsf` uploads only reviewed `.apk` files from `mobsf-upload/` or `--mobsf-upload-dir`; it does not automatically upload extracted device APKs. MobSF workflows retain upload, task-polling, report and status evidence, and only mark a report complete when its APK hashes and core sections validate. EMBA runs against a user-supplied local firmware image or directory and retains external output without normalizing every external rule into Hexwarden findings.

## Common evidence files

Every run contains `report.txt`, `report.json`, `audit.log`, `capabilities.json` and `inventory.json`. Module-specific evidence is stored below `evidence/<module>/`. Common derived artifacts include:

- `apps.json` and decoded APK manifests under `apks/`
- `permission-correlation.json`
- `shared-uids.json` and Drozer `agent-checks.json`
- MobSF status, endpoint responses and validated `report_json.json`
- `traffic.pcap` and capture metadata for passive analysis
- Bluetooth SDP and structured BLE results

Use [REPORT_FORMAT.md](REPORT_FORMAT.md) for coverage states, finding fields and evidence locators. Use [PLAN.md](PLAN.md) for the module-level roadmap and known gaps.
