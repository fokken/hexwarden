# Hexwarden design and implementation plan

Hexwarden is a host-side Python CLI targeting one authorized Android device over ADB. The core works with the Python standard library. Every requested audit area has its own module; shared app extraction and manifest parsing avoid pulling the same APK repeatedly.

See [CHECKS.md](CHECKS.md) for the complete collection and analysis reference, including evidence artifacts and current limits.

## Architecture

1. Validate CLI scope and discover/select an authorized device. Refuse ambiguous multi-device selection.
2. Create a private, unique run directory below `data/` and start a file logger.
3. Discover host/device commands, dependencies, services and requested root capability. Run selected collectors sequentially with deadlines, a fixed serial, and explicit root opt-in. Skip known missing capabilities, attempt unknown ones, stream output to files and record command provenance.
4. Record automated checks explicitly, including no-match and blocked outcomes. Separate collection, analysis and manual-verification coverage. Findings carry stable IDs, affected assets, classification, focused evidence, remediation and verification guidance. Missing data never means secure.
5. Optionally pull installed APKs, decode manifests with Androguard, correlate permission declarations/requests/guards, and check verified signing certificates against a user-supplied blocklist. In a separate opt-in phase, upload user-selected APKs from `mobsf-upload/` to an explicitly configured MobSF server.
6. Optionally invoke Drozer CLI modules for package/component inspection, UID groups, effective grants and agent-context filesystem probes, or run EMBA against a supplied local firmware image.
7. Write incremental text/JSON reports and a final SHA-256 evidence inventory, including failure/interruption reports.

## Categories and coverage

| Category | Module | Automated coverage | Limits / additional validation |
|---|---|---|---|
| System hardening | `developer_options` | Developer settings, USB/wireless ADB, TCP port properties | Authentication/reachability need separate validation |
| System hardening | `screen_lock` | Trust, policy, biometric/fingerprint/face dumps | PIN/pattern strength and enrollment require on-device review |
| System hardening | `encryption` | Crypto properties, volume inventory | Does not verify key protection or all volumes |
| System hardening | `unknown_sources` | Legacy setting and per-user installer AppOps | OEM/device-management policy varies |
| System hardening | `outdated_os` | System/vendor patch dates and configurable age policy | No claim of CVE completeness or OEM support status |
| System hardening | `backup` | Backup manager status, settings and dump | Not equivalent to ADB backup eligibility; app manifests also collected |
| System hardening | `certificates` | System/Conscrypt/user CA export; OpenSSL metadata/fingerprints; test-name heuristics | Needs trusted fingerprint baseline; per-app trust differs |
| System hardening | `filesystem_acls` | SELinux mode, directory labels, mounts, bounded world-writable file search | Optional Drozer integration adds actual list/read/write probes, scoped to its agent identity |
| System hardening | `secrets_trust` | HAL/Binder/keystore inventory, TEE/TPM device nodes, candidate secret filenames | No key extraction; attestation and HSM semantics need vendor/test-app support |
| System hardening | `verified_boot` | Boot lock, verified-boot state, verity mode, build tags | Runtime properties are not independent attestation |
| System hardening | `updates_integrity` | A/B properties, updater dumps, OTA trust-file metadata | OTA verification, rollback and Play Integrity require firmware/backend review |
| Interfaces | `usb` | USB functions, sysfs class/device IDs, input and block devices | Device acceptance requires physical HID/Ethernet/storage tests |
| Networking | `network` | Addresses, links, routing/policy rules, sockets correlated with PIDs/processes/package UIDs, Wi-Fi/Ethernet/tethering, iptables/nftables policy summaries, network namespaces, eBPF inventory and forwarding state | Root for firewall/eBPF; namespace/offload/OEM limits; attribution and listening do not prove remote reachability |
| Networking | `radamsa_fuzz` | Separate, explicit TCP/UDP Radamsa campaigns with seed files, bounded payloads, durable timestamped journals, response metadata and ADB logcat/crash-buffer monitoring | Requires manual target selection and Radamsa; crash markers still require timestamp correlation and triage; sending payloads can alter state or crash services |
| Networking | `passive_network` | Configurable-duration/interface/snaplen `tcpdump` PCAP retained with capture metadata; tshark payload-filtered cleartext protocol candidates with frame references and redacted metadata | Device tcpdump/timeout, permissions and host tshark; no decryption; STARTTLS/QUIC/proprietary protocols need review |
| Wireless | `bluetooth` | Local inventory; optional host MAC-targeted SDP, BLE services/properties/descriptors, BLE reads and notification subscriptions, advertised RFCOMM/L2CAP connection probes and bounded target-scoped Classic/BLE payload probes | Host adapter/tools required; existing bonds affect results; payloads/subscriptions can change state or expose data and do not prove unauthenticated access |
| Running applications | `logging_secrets` | Bounded logcat with credential/private-key-marker heuristics | Raw data sensitive; findings omit matched values; incomplete heuristic coverage |
| Running applications | `privileged_apis` | Privileged app detection; exported service/provider candidates, with configurable package-prefix exclusions (defaults: `com.google`, `com.android`) | Requires APK extraction + Androguard; runtime permission checks need review; excluded packages are coverage scope |
| Running applications | `custom_permissions` | Permission declarations, requesters and guarded component correlation; weak guards and multiple declarers; filtered `HW-APP-003` candidates | Actual ownership, grants, SDK conditions and split merging require validation; package-prefix exclusions are scope |
| Running applications | `app_extraction` | Bulk base/split APK extraction, hashes, manifests, verified signer blocklists with additive package entries, MobSF | Visible installed packages only; optional tools required; rotation/device-specific signer selection requires review |
| Running applications | `app_apis` | Activities, aliases, receivers, providers and services; permission inheritance; filtered `HW-APP-001` candidates | Static candidates, not exploitation; split/resource/runtime overrides and package-prefix exclusions need review |

## Validation strategy

MobSF tests cover synchronous and queued scans, matching task identities, unsuccessful tasks, deadline expiry, transient retries without scan resubmission, malformed or mismatched reports, redirects/authentication failures, and parent-worker interruption and coverage handling. The adapter polls within a hard per-APK deadline and retains response/status evidence; live-server validation remains outstanding.

Drozer tests distinguish requested from granted permissions, verify actual file-open failures, ensure write-probe cleanup, retain incomplete cleanup records, and check CLI command quoting and supported-module selection. UID tests cover visible peers, separate Android users, privilege prioritization and missing inventory. Signer tests cover blocklist validation, rejection of old allowlists, additive package blocks, multiple signers, split APK outcomes and incomplete verification output. Permission correlation tests cover request SDK conditions, provider path guards, duplicate declarations and disabled components. Capability tests cover known missing and unknown commands, service inventory parsing, root context selection and capture prerequisites.

Unit tests cover manifest permission inheritance, provider defaults by target SDK, asymmetric provider permissions, disabled components, custom protection bits, and log secret redaction. A simulated ADB integration test runs all 20 collection modules and checks reports, evidence paths, findings and file permissions; the separate Radamsa module is exercised with dedicated campaign tests. Bluetooth tests cover SDP endpoint association, invalid endpoint filtering, opt-in CLI validation, BLE discovery/read/pair/write/fuzz behavior, denied reads, absent targets, deadlines, socket closure and exclusion of read values from findings. Failure tests cover missing ADB, denied commands and deadlines. Physical-device and external-service validation remains necessary before relying on findings operationally.

## Follow-on work requiring target-specific inputs

* Bluetooth device-specific write semantics, application protocol validation and independently measured link security beyond the implemented target-scoped probes.
* On-device KeyMint/StrongBox attestation helper with independent verification and trusted roots.
* OEM OTA, projection-mode, firewall/eBPF, and custom HSM adapters.
* Approved production APK/CA/AVB fingerprint baselines and firmware package samples.
* Effective merged manifest/resource analysis and broader runtime authorization checks; the manifest permission map and Drozer UID groups are implemented.

These are explicit coverage gaps, not implemented capabilities. The current tool collects the supporting evidence and reports the gaps.
