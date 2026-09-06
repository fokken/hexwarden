# Optional integrations

[Back to README](../README.md) · [Linux installation](../README.md#installation-linux)

Install and prepare each external analyzer separately; Hexwarden does not install them. The Python `mobsf` extra supplies the HTTP client, not the MobSF server.


## MobSF

Configure a prepared MobSF server and set `MOBSF_API_KEY` in your environment. Install Hexwarden's `mobsf` extra. Selecting `--mobsf-url` explicitly enables upload of the extracted APKs and requires `--extract-apks` and the `app_extraction` module. Loopback HTTP is supported; remote servers require HTTPS. Credentials are not placed in command logs. The adapter uploads each base/split APK separately, requests a static scan, then saves the JSON response using [MobSF's API](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/views/api/api_static_analysis.py).

```sh
python3 -m hexwarden scan --modules app_extraction --extract-apks \
  --mobsf-url http://127.0.0.1:8000 --package com.example.app
```

Responses are saved under `integrations/mobsf/<package>-<apk-index>/` as `upload.json`, `scan.json` and `report_json.json`. The adapter requests the report once; it does not poll queued scans or validate report completeness. Inspect responses from asynchronous deployments manually. External results are retained as separate JSON evidence, not normalized into native findings. Hexwarden's [permission correlation and approved signer checks](../README.md#application-trust-and-permission-correlation) complement this broader analysis.

## Drozer

Drozer requires a running, reachable agent and installed host CLI. All interaction is through `drozer console connect`; Hexwarden does not import Drozer into its process or connect directly to its protocol. Prepare the connection yourself and verify that the agent is on the ADB-selected device. See the [Drozer project](https://github.com/ReversecLabs/drozer).

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
* PackageManager application UIDs and visible same-UID peers. With `--package`, selected packages seed the inventory; without it, installed packages visible to the agent are enumerated. `--max-apps` caps inspected starting packages, but peer names can exceed the cap. An interrupted or truncated inventory is not counted as complete.
* Effective `PackageManager.checkPermission` results for requested permissions of the agent and selected packages. Built-in package-info output alone is not treated as granted permissions.
* Directory-listing attempts against `--drozer-list-path` targets (default `/data`, `/data/local/tmp`, `/sdcard`). There is no recursive scan. Up to `--drozer-entry-limit` names are retained per directory, default 50, maximum 1,000; Android's directory-list API still enumerates the directory internally.
* A one-byte read attempt against each `--drozer-read-path` regular file, with the byte discarded. Empty files can still demonstrate successful opening. No special devices or FIFOs are opened.
* Optional `--drozer-write-dir` tests using Java-created unique `hexwarden-*.probe` files. Each probe writes one byte and attempts deletion in a cleanup block. Probe creation is logged immediately; an unconfirmed cleanup is reported. Forced termination can leave a probe behind.

Actual probe outcomes and agent identity are saved in `integrations/drozer/agent-checks.json` and included in findings. UID groups are saved in `evidence/drozer/shared-uids.json`. Full UIDs keep Android users separate. Shared groups and system-range app IDs (below 10,000) generate observations; system-range IDs, observed `/priv-app/` paths and sensitive grants raise their review priority. The helper reports assigned package identities, not live process UIDs, root access or equivalent SELinux privileges. Package visibility can hide peers, and grants are inspected only for the agent and selected packages.

Access successes are informational observations, not automatically vulnerabilities. ADB separately collects package AppOps, accessibility/notification-listener settings and device policy. Package grants alone do not prove AppOps authorization or successful use of a privileged API. The agent's Android user may differ from `--user`; that mismatch is reported. Permission maps, APK signer policy and agent grants remain separate evidence; they are not automatically merged into an effective authorization verdict.

Use `--drozer-bin /path/to/drozer` for a custom CLI. The per-run configuration is isolated from your home Drozer configuration. This adapter uses a prepared endpoint that can connect noninteractively without an agent password; `--no-password` and `--no-color` are selected if supported by CLI help. Password-protected/interactive TLS setups need additional adapter support and may fail with a recorded coverage gap. No automatic forwarding or privileged execution occurs.

The bundled helper targets the current Reversec agent permission namespace. CLI/module APIs were inspected against [Drozer source revision d992f63](https://github.com/ReversecLabs/drozer/tree/d992f6378d42680ea96ee03eff4117f150e1049c). Older agents can expose different capabilities; an unavailable helper is reported rather than replaced with weaker permission-bit evidence.

## EMBA

Provide an already obtained firmware image or extracted directory and a prepared EMBA installation. EMBA's dependencies and execution environment are managed separately; no firmware partition dumping occurs. See [EMBA](https://github.com/e-m-b-a/emba).

```sh
python3 -m hexwarden scan --emba /opt/emba/emba \
  --emba-firmware /path/to/firmware.bin --integration-timeout 7200
```
