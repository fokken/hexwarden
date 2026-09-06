# Application analysis

[Back to README](../README.md) · [Linux installation](../README.md#installation-linux)

## Setup

Manifest decoding and permission correlation use the `apps` extra. Signature verification and blocklist matching need host `apksigner` and Java:

```sh
python3 -m pip install -e '.[apps]'
sudo apt install apksigner
```

The distribution's [`apksigner` package](https://packages.ubuntu.com/noble/apksigner) installs its Java dependency. If using Android SDK Build Tools instead, expose its `apksigner` executable on `PATH`.

## Certificate blocklist

Use MobSF for broad APK analysis (`--mobsf-url`). Hexwarden correlates installed-app permissions and flags verified signers matching your certificate blocklist:

```sh
hexwarden scan --modules app_extraction custom_permissions --extract-apks \
  --blocked-certs blocked-certs.json --package com.example.app
```

Save the following as `blocked-certs.json` before running the command. Replace the example with the **certificate SHA-256** fingerprint of an unwanted signer (not the APK hash or public-key hash). Add more fingerprints to block additional certificates:

```json
{
  "blocked_sha256": ["0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"],
  "packages": {}
}
```

`blocked_sha256` applies to every collected APK. Optional `packages` entries map exact package names to additional blocked fingerprints; they cannot cancel global blocks. Any matching verified signer on a base/split APK produces a finding. An empty blocklist produces no matches. Fingerprints accept upper/lowercase hexadecimal and optional colon separators. Missing tools, failed verification and unrecognized output are **not evaluated**. A `no_match` result does not establish trust or safety. Use the distribution package or Android SDK Build Tools described above and put `apksigner` on PATH; certificate comparison does not require Androguard. Signing-key rotation and device-specific signer selection still need review. The normalized policy and per-APK results, including matched fingerprints, are saved under `evidence/app_extraction/` as `blocked-certs.json` and `signer-policy.json`. Verification uses Android's [apksigner](https://developer.android.com/tools/apksigner).

`--blocked-certs` requires `--extract-apks` and selection of `app_extraction`. Without a policy, signature output is still collected when `apksigner` is available, but blocklist matching is not evaluated. The policy applies only to collected APKs; it does not require listed packages to be installed or prove that every split was extracted. This is an audit check; Hexwarden does not uninstall or prevent installation of matching apps.

The former `--approved-certs` option has been removed. Old policies containing `default` are rejected: create a new blocklist of unwanted certificates rather than copying trusted certificates from an allowlist.

## Permission correlation

`custom_permissions` requires the `apps` extra and saves `permission-correlation.json`: declaring apps, requesting apps (including SDK conditions), and guarded components, including provider read/write and path permissions. It flags weak permissions guarding enabled exported components and multiple declaring packages. Missing declarations are scoped inventory gaps, not vulnerabilities. Run without `--package` for wider correlation. Requests are not grants; split merging, runtime checks and effective ownership require validation. See Android's [custom permission documentation](https://developer.android.com/guide/topics/permissions/defining).

## Privileged API candidates

`privileged_apis` reports exported, enabled services and providers without manifest permission guards for packages inferred to be privileged. To reduce platform false positives, packages whose names start with `com.google` or `com.android` are excluded by default:

```sh
hexwarden scan --modules privileged_apis --extract-apks
```

Add more exclusions with repeated `--privileged-api-exclude-prefix` options. To include the default platform prefixes, use `--privileged-api-no-default-excludes`. Filtering is a coverage decision and is recorded in the module limitations; it does not prove that an excluded package is safe. Runtime authorization, effective grants and actual privileged operations still require validation.

## Shared UIDs through Drozer

With `--drozer`, the existing CLI-driven agent probe also records full package UIDs and visible same-UID peers in `evidence/drozer/shared-uids.json`. System-range UIDs, privileged installation paths and observed sensitive grants prioritize review. Android users remain separate. `--package` restricts starting packages while including their visible UID peers; without it, UID inventory covers apps visible to the agent. Grant probes still follow the existing selected-package scope. These are [PackageManager identities](https://developer.android.com/reference/android/content/pm/PackageManager), not proof that an app is currently running or has root access. Raw agent evidence, findings and coverage gaps remain available in the text/JSON reports.

Add `--drozer` after preparing the [Drozer integration](INTEGRATIONS.md#drozer). `--max-apps` caps UID starting-package inspection as well as APK collection; same-UID peers can exceed that cap. Broader permission correlation benefits from omitting `--package`, but update the certificate policy for that wider scope first.
