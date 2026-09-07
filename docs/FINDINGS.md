# Findings catalog

Hexwarden finding IDs are stable rule identifiers. A finding is an observation
or review candidate, not a universal vulnerability verdict; use its verification
guidance and referenced evidence before assigning impact.

| Code | Title | Classification | Recommended action | Verification |
|---|---|---|---|---|
| `HW-APP-001` | Exported component without manifest permission | review_candidate | Disable unintended export or enforce suitable permissions and runtime authorization. | Resolve effective manifests and test authorization as an unprivileged caller, including provider URI/path permissions. |
| `HW-APP-002` | Privileged app API exposure candidate | review_candidate | Restrict sensitive privileged operations to authorized callers. | Confirm effective privileged grants and runtime caller checks. |
| `HW-APP-003` | Custom permission with weak protection level | review_candidate | Use protection appropriate to the protected operation; signature permissions may suit trusted IPC. | Map permission ownership and consumers, then test meaningful access from an untrusted caller. |
| `HW-APP-004` | Debuggable application | observation | Disable debuggable in production builds where debugging is not required. | Verify the installed release variant and effective manifest. |
| `HW-APP-009` | APK signer outside approved certificate policy | review_candidate | Confirm the expected signer and replace unapproved builds or update the reviewed policy. | Compare verified certificate fingerprints with an independently approved baseline. |
| `HW-APP-010` | Custom permission relationship requires review | review_candidate | Review weak permissions guarding exported components and conflicting declarations. | Confirm effective ownership and grants through PackageManager and manual runtime testing. |
| `HW-APP-011` | APK signer matches certificate blocklist | review_candidate | Review and replace builds signed with unwanted certificates. | Confirm the matched certificate fingerprint and affected APK; review key rotation. |
| `HW-BOOT-001` | Bootloader reports unlocked | review_candidate | Restore the vendor-approved production boot state and signing trust. | Use vendor procedures and independent boot/attestation evidence. |
| `HW-BOOT-002` | Verified boot requires review | review_candidate | Use the intended AVB trust root and approved signed firmware. | Verify boot-state meaning and actual signing key. |
| `HW-BOOT-003` | dm-verity enforcement requires review | review_candidate | Restore intended verified-partition enforcement. | Validate verity behavior independently of runtime properties. |
| `HW-BOOT-004` | Build tagged test-keys | review_candidate | Use approved production signing keys for production images. | Inspect actual image/APK signing fingerprints. |
| `HW-BT-001` | Bluetooth Classic services advertised | observation | Review whether each advertised service is required. | Compare SDP records with intended profiles. |
| `HW-BT-002` | Bluetooth Classic endpoint accepts host connection | observation | Restrict unused endpoints and enforce pairing/authentication policy. | Repeat from a controlled bond state and verify application authorization. |
| `HW-BT-003` | BLE characteristic advertises write support | review_candidate | Require appropriate authentication and authorization for sensitive writes. | Use an approved payload and controlled bond state. |
| `HW-BT-004` | BLE characteristic readable in current host security context | observation | Review whether the exposed value is appropriate. | Compare access in controlled paired/unpaired contexts. |
| `HW-BT-005` | BLE characteristic accepted an explicit write probe | observation | Require intended authentication and authorization before state-changing writes. | Repeat with controlled paired/unpaired states and an approved payload. |
| `HW-BT-006` | Bluetooth Classic endpoint accepted an explicit payload | observation | Require intended authentication and authorization before accepting application data. | Repeat from controlled bond states with an approved payload. |
| `HW-BT-007` | BLE characteristic accepted a notification subscription | observation | Require intended authentication and authorization before exposing notifications. | Repeat from controlled paired/unpaired states. |
| `HW-CA-001` | Possible test/debug trust anchor | review_candidate | Remove unapproved test anchors. | Compare the certificate fingerprint with an approved baseline. |
| `HW-DEV-001` | Developer setting enabled | observation | Disable unnecessary development/debugging features after assessment. | Re-read the setting and verify the intended workflow. |
| `HW-DEV-002` | Network ADB configured | review_candidate | Disable network ADB when unused or restrict reachability and require authentication. | Correlate the port with listeners and test the network boundary. |
| `HW-DZ-001` | Sensitive package permissions granted | observation | Review sensitive grants against package roles. | Inspect grants with AppOps and actual API authorization. |
| `HW-DZ-002` | Filesystem access succeeded from Drozer agent | observation | Review whether the agent identity should have the demonstrated access. | Compare path, UID, SELinux context, and intended policy. |
| `HW-DZ-003` | Drozer write probe cleanup not confirmed | review_candidate | Inspect and remove a remaining probe file. | Confirm the exact probe path no longer exists. |
| `HW-DZ-004` | Shared or system-range application UID | observation | Review whether packages share an appropriate trust boundary. | Confirm UID, grants, SELinux domains, and running process identities. |
| `HW-DZ-005` | Drozer readable-file scanner found agent-readable paths | observation | Review whether each path should be readable by the agent context. | Repeat from the intended identity and inspect approved files. |
| `HW-ENC-001` | Storage reports unencrypted | review_candidate | Use the vendor-supported encryption configuration. | Confirm volume-specific encryption and key protection. |
| `HW-FS-001` | SELinux not enforcing | review_candidate | Restore approved enforcing SELinux configuration. | Confirm enforcing mode and review policy behavior. |
| `HW-FS-002` | World-writable files require review | review_candidate | Restrict unintended file write access. | Test access from the relevant app context and correlate DAC/SELinux. |
| `HW-INSTALL-001` | Legacy unknown-source installation enabled | observation | Disable unnecessary installation paths. | Check Android version, installer AppOps, and device policy. |
| `HW-INSTALL-002` | Apps allowed to request APK installation | review_candidate | Restrict APK installation permission to approved installers. | Review installers and confirm the authorization flow. |
| `HW-LOG-001` | Potential secrets in logcat | review_candidate | Remove sensitive logging and rotate exposed credentials. | Inspect referenced lines securely and reproduce the logging path. |
| `HW-NET-001` | Services bound to wildcard addresses | review_candidate | Bind services to required interfaces and restrict access. | Identify the owner and test reachability from relevant networks. |
| `HW-NET-002` | IP forwarding enabled | observation | Keep forwarding only where the routing role requires it. | Compare forwarding, routes, tethering, and interface roles. |
| `HW-NET-003` | Potential cleartext application traffic | review_candidate | Require authenticated transport encryption. | Inspect referenced frames and repeat a representative capture. |
| `HW-NET-004` | Firewall policy requires review | review_candidate | Apply an explicit default-deny policy where appropriate. | Review IPv4/IPv6/eBPF policy and test reachability. |
| `HW-PATCH-001` | Security patch exceeds age policy | review_candidate | Install an approved update or document an exception. | Validate patch dates and update provenance. |

The authoritative machine-readable definitions remain in
[`android_audit/findings.py`](../android_audit/findings.py). Reports include the
matching rule metadata, affected asset, evidence references, remediation, and
verification text for each emitted finding.
