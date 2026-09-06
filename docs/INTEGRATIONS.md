# Optional integrations

[Back to README](../README.md) · [Linux installation](../README.md#installation-linux)

Install and prepare each external analyzer separately; Hexwarden does not install them. The Python `mobsf` extra supplies the HTTP client, not the MobSF server.


## MobSF

Configure a prepared MobSF server and set `MOBSF_API_KEY` in your environment. Install Hexwarden's `mobsf` extra. MobSF upload is a separate phase from APK extraction: first run `--extract-apks`, inspect the collected APKs, copy the ones you want to analyze into `mobsf-upload/`, then run `--mobsf`. Loopback HTTP is supported; remote servers require HTTPS. Credentials are not placed in command logs. The adapter uploads each selected APK separately, requests a static scan, and saves the JSON response using [MobSF's API](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/MobSF/views/api/api_static_analysis.py).

```sh
# Phase 1: extract installed APKs for review
python3 -m hexwarden scan --modules app_extraction --extract-apks \
  --package com.example.app

# Copy selected files from data/<run-id>/apks/ into ./mobsf-upload/
mkdir -p mobsf-upload
cp data/<run-id>/apks/com.example.app/000.apk mobsf-upload/

# Phase 2: upload only the reviewed APKs
python3 -m hexwarden scan --mobsf \
  --mobsf-url http://127.0.0.1:8000 \
  --integration-timeout 1800 --mobsf-poll-seconds 5
```

Use `--mobsf-upload-dir /path/to/folder` to select another folder. Only regular files ending in `.apk` (case-insensitive) are selected; other files are ignored. The default folder must exist before the scan. `--mobsf` does not run APK extraction and does not upload APKs from a previous run automatically.

The adapter uploads once and submits one scan request per extracted APK. Synchronous scans proceed to report retrieval. When MobSF returns a task ID, Hexwarden polls `/api/v1/tasks` for that task and APK hash until successful completion; failed tasks stop the workflow. Responses without a task ID, including an already-enqueued response, proceed to report polling. A missing report is retried. Report/task polling also retries HTTP 429/502/503/504 and connection/timeouts. Authentication errors, redirects, other HTTP failures and unrecognized payloads stop the workflow. An ambiguous scan connection failure proceeds to report polling without resubmitting the scan.

`--mobsf-poll-seconds` sets the polling interval (default 5). `--integration-timeout` is a hard **per-APK workflow deadline**, covering hashing, upload, scan and polling (default 1,800 seconds). A separate worker process enforces this even if an HTTP request stalls. `--timeout` bounds individual upload/task/report requests; a synchronous scan request can use the remaining workflow budget. Timeout or interruption stops local waiting but does not cancel server work. APKs are processed sequentially, so the deadline is not a limit for the entire audit.

Evidence is saved under `integrations/mobsf/<package>-<apk-index>/`:

| File | Contents |
|---|---|
| `status.json` | Latest stage, attempt count, APK hashes, task ID when available, and final workflow status |
| `NNNN-<endpoint>.json` | HTTP status and parsed JSON response for each attempt, or a transport error type |
| `upload.json`, `scan.json` | Accepted upload and scan responses, when received |
| `report_json.json` | Validated APK report only |

Final status is `completed`, `failed`, `timed_out`, or `interrupted`. Report validation checks local MD5/SHA-256 identity, a package name, and the expected permission, manifest, code and certificate analysis sections. Empty analysis sections are permitted; this validates report structure and identity, not completeness of every MobSF analyzer. Queued task success alone is insufficient. A `mobsf_report` coverage check records success or the gap, including missing dependencies/API key. External findings remain separate JSON evidence, not normalized into native findings.

Malformed or incompatible reports remain response evidence and never become successful analysis. Non-JSON bodies are marked as such rather than retained; request credentials and transport exception messages are not logged. JSON responses may still contain sensitive server or APK data. Task tracking follows MobSF's [asynchronous task API](https://github.com/MobSF/Mobile-Security-Framework-MobSF/blob/master/mobsf/StaticAnalyzer/views/common/async_task.py); forks with different response formats require adapter changes. Live-server validation remains outstanding. Hexwarden's [permission correlation and certificate blocklist checks](APPLICATIONS.md) complement this broader analysis.

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

# Scan selected directories for files readable from the Drozer agent context
python3 -m hexwarden scan --drozer \
  --drozer-readable-path /vendor \
  --drozer-readable-path /system/etc
```

The integration discovers available modules using the CLI's `list` command. It runs built-in `app.package.list`, global `app.package.info`, global `app.package.shareduid`, and global component inventory modules `app.activity.info`, `app.service.info`, `app.provider.info` and `app.broadcast.info`, each without a package argument. This collects the complete package/component inventory exposed by the agent. It does not use `app.package.attacksurface` for a single selected package. Missing modules are skipped with a coverage reason. `--package` and `--max-apps` apply to the separate per-package grant/AppOps checks and bundled agent probes; they do not narrow the global inventory modules.

The bundled `hexwarden.audit` module is likewise invoked through the CLI. A per-run `.drozer_config` and module repository under `integrations/drozer/` load it without changing your home configuration or installing an APK. Its checks are:

* Agent package, UID, PID, Android user, package GIDs and SELinux context where accessible.
* PackageManager application UIDs and visible same-UID peers. With `--package`, selected packages seed the inventory; without it, installed packages visible to the agent are enumerated. `--max-apps` caps inspected starting packages, but peer names can exceed the cap. An interrupted or truncated inventory is not counted as complete.
* Effective `PackageManager.checkPermission` results for requested permissions of the agent and selected packages. Built-in package-info output alone is not treated as granted permissions.
* Directory-listing attempts against `--drozer-list-path` targets (default `/data`, `/data/local/tmp`, `/sdcard`). There is no recursive scan. Up to `--drozer-entry-limit` names are retained per directory, default 50, maximum 1,000; Android's directory-list API still enumerates the directory internally.
* A one-byte read attempt against each `--drozer-read-path` regular file, with the byte discarded. Empty files can still demonstrate successful opening. No special devices or FIFOs are opened.
* The built-in `scanner.misc.readablefiles` module against each explicit `--drozer-readable-path`. This is an opt-in directory scan performed by Drozer in the agent context; it does not recursively copy files or retain file contents. Path-shaped result rows receive `HW-DZ-005`, while the complete raw module output remains evidence. Scan behavior and recursion depend on the installed Drozer module version.
* Optional `--drozer-write-dir` tests using Java-created unique `hexwarden-*.probe` files. Each probe writes one byte and attempts deletion in a cleanup block. Probe creation is logged immediately; an unconfirmed cleanup is reported. Forced termination can leave a probe behind.

Actual probe outcomes and agent identity are saved in `integrations/drozer/agent-checks.json` and included in findings. UID groups are saved in `evidence/drozer/shared-uids.json`. Full UIDs keep Android users separate. Shared groups and system-range app IDs (below 10,000) generate observations; system-range IDs, observed `/priv-app/` paths and sensitive grants raise their review priority. The helper reports assigned package identities, not live process UIDs, root access or equivalent SELinux privileges. Package visibility can hide peers, and grants are inspected only for the agent and selected packages. Readable-file scans identify paths accessible to the agent, not necessarily world-readable files or sensitive data.

Access successes are informational observations, not automatically vulnerabilities. ADB separately collects package AppOps, accessibility/notification-listener settings and device policy. Package grants alone do not prove AppOps authorization or successful use of a privileged API. The agent's Android user may differ from `--user`; that mismatch is reported. Permission maps, APK signer policy and agent grants remain separate evidence; they are not automatically merged into an effective authorization verdict.

Use `--drozer-bin /path/to/drozer` for a custom CLI. The per-run configuration is isolated from your home Drozer configuration. This adapter uses a prepared endpoint that can connect noninteractively without an agent password; `--no-password` and `--no-color` are selected if supported by CLI help. Password-protected/interactive TLS setups need additional adapter support and may fail with a recorded coverage gap. No automatic forwarding or privileged execution occurs.

The bundled helper targets the current Reversec agent permission namespace. CLI/module APIs were inspected against [Drozer source revision d992f63](https://github.com/ReversecLabs/drozer/tree/d992f6378d42680ea96ee03eff4117f150e1049c). Older agents can expose different capabilities; an unavailable helper is reported rather than replaced with weaker permission-bit evidence.

## EMBA

Provide an already obtained firmware image or extracted directory and a prepared EMBA installation. EMBA's dependencies and execution environment are managed separately; no firmware partition dumping occurs. See [EMBA](https://github.com/e-m-b-a/emba).

```sh
python3 -m hexwarden scan --emba /opt/emba/emba \
  --emba-firmware /path/to/firmware.bin --integration-timeout 7200
```
