# Hexwarden report format, version 2

`report.json` now has `schema_version: 2`. It separates execution coverage from findings and records the actual automated checks that ran. `report.txt` presents the same findings, guidance, collection/analysis states, and blocked checks.

## Findings

Each finding contains:

| Field | Meaning |
|---|---|
| `rule_id` | Stable catalog identifier, such as `HW-APP-002`; independent of the display title |
| `id` | Rule ID plus a deterministic hash of the affected asset; independent of run directory, timestamps and changing descriptive detail |
| `asset` | Device/user and applicable package, component, path, property, Bluetooth endpoint or certificate identifiers |
| `title`, `detail` | Observation and supporting context; raw secret values are not added to native finding text |
| `classification` | `observation` or `review_candidate` for current rules; `confirmed_weakness` is reserved for future rules with sufficient verification |
| `severity` | Triage priority, not proof of exploitability |
| `confidence` | Confidence in the observation/heuristic result, independent of classification |
| `verification_status` | `observed` for observations, `pending` for review candidates |
| `remediation` | Recommended action, contingent on verifying whether the behavior violates the deployment's intended policy |
| `verification` | Steps needed to assess the finding and validate remediation |
| `evidence` | Array of objects containing a run-relative `path` and optional `locator` |
| `additional_observations` | Additional details for the same rule/asset encountered within the module, when different |

Finding IDs are stable **for the same supplied asset identity**. A changed ADB serial/user or Bluetooth private address changes that identity. Findings for the same rule/asset within a module merge evidence references; different rules intentionally remain separate, including generic versus privileged API exposure.

A high-confidence observation is not a confirmed vulnerability. For example, successful Drozer file access confirms that operation in the agent context, while a policy violation still needs review. An exported privileged component is a medium-severity review candidate until its authorization and meaningful privileges are assessed.

## Evidence references

A finding references the relevant command output or decoded artifact, rather than every command previously executed by the module. Example:

```json
{
  "rule_id": "HW-LOG-001",
  "classification": "review_candidate",
  "evidence": [
    {
      "path": "evidence/logging_secrets/0042-logcat.txt",
      "locator": {"lines": [12, 47]}
    }
  ]
}
```

This is a structural example, not real device evidence. Locator forms are:

* `lines`: one-based text line numbers for log matches.
* `frames`: packet frame numbers reported by tshark, associated with the PCAP.
* `json_pointer`: a pointer into the saved Drozer `agent-checks.json` event array.
* `component` plus `type`, `permission`, or `element` plus `attribute`: semantic selectors within a decoded manifest XML file.
* `service_uuid` plus `characteristic_handle`: identifies a BLE characteristic in worker output.

A reference without a locator applies to the referenced output as a whole. Command evidence entries retain `label`, arguments, return code, timeout, truncation state and stderr path. Capabilities and cached app artifacts may be referenced from another module's evidence directory. Raw artifacts and external analyzer reports can still contain sensitive information.

## Application analysis artifacts

Paths below are relative to the run directory. Findings remain in both `report.txt` and `report.json`; the detailed inventories are JSON evidence.

| Artifact | Contents |
|---|---|
| `evidence/app_extraction/approved-certs.json` | Normalized policy snapshot when `--approved-certs` is supplied |
| `evidence/app_extraction/signer-policy.json` | Per extracted APK: package, path, signature evidence, allowed fingerprints and policy status |
| `evidence/custom_permissions/permission-correlation.json` | Permission declarations, requesters, protected components and scoped declaration status |
| `integrations/drozer/agent-checks.json` | Agent identity and individual probe events |
| `evidence/drozer/shared-uids.json` | Full UID groups, visible packages, privilege indicators and source event references |

Signer policy status is `approved`, `unapproved`, or `not_evaluated`. Approval requires successful signature verification and all parsed current certificate fingerprints to be allowed. `HW-APP-009` reports unapproved signers; unavailable verification is a coverage gap. Missing APKs have not-evaluated checks rather than fabricated per-APK rows. Approval does not establish scan-wide completeness or application safety.

Permission declaration status is `observed`, `multiple_declarers`, or `not_observed_in_scope`. It describes decoded manifests, not effective PackageManager ownership or permission grants. `HW-APP-010` flags weak guards on enabled exported components or multiple declaring packages. `HW-DZ-004` records shared or system-range UIDs as observations; severity prioritizes review rather than confirming a vulnerability.

## Coverage

Every audit module has a `coverage` object with independent sections:

**`collection`** counts unique attempted commands, successful commands, failed commands, known skipped commands and truncated outputs. Its status is `completed`, `partial`, `failed`, `skipped`, or `not_performed`. This measures command execution only: exit success does not validate the contents or establish security. Derived artifacts do not inflate command counts.

**`analysis`** counts explicitly recorded checks. Its status is `completed`, `partial`, `failed`, or `not_performed`. A collector-only module reports `not_performed` even if every command succeeded. Completed analysis means the recorded implemented checks were evaluated; it does not mean that every conceivable test in the area was performed. Truncated source output and interrupted analysis cannot produce completed analysis.

**`manual_verification`** records whether follow-up is required and the reasons, including module limitations, missing checks and review candidates. Automated checks can complete while manual verification remains required.

`analysis_checks` lists `check_id`, `status` (`evaluated` or `not_evaluated`), scope, reason and evidence. No-match runs still record successful evaluation. Missing or unrecognized input is not counted as a clean result. A failed access probe whose security meaning cannot be established is conservatively recorded as not evaluated, with its raw outcome retained.

`skipped_checks` retains preflight capability reasons and requested commands. Some semantic prerequisites (such as missing decoded manifests) are represented as not-evaluated analysis checks rather than skipped shell commands.

The older module `status` field remains a coarse execution/limitation indicator for compatibility. It can be `partial` solely because manual interpretation is required, even when command collection and the implemented analysis completed. Prefer the new coverage fields when assessing completeness.

## Run summary

`summary` includes finding counts by severity and classification, module counts by collection and analysis status, the number requiring manual verification, and requested modules that never started. This also exposes incomplete/interrupted runs. Preflight remains in `capabilities`, separate from audit module counts.

**No findings is not a pass.** Read analysis coverage and manual-verification requirements alongside finding counts. No security score or pass/fail verdict is inferred.

## Migration from version 1

* Finding evidence entries changed from path strings to `{ "path": "...", "locator": ... }` objects. Read `entry.path` instead of using the entry as a string.
* New finding metadata, coverage, `analysis_checks`, and `summary` are additive.
* Module command-evidence objects, raw artifact locations, exit codes and coarse `status` semantics remain compatible.
* Display titles may change; use `rule_id` for rule matching and `id` for rule/asset identity.
* External MobSF/EMBA results remain separate evidence; this release does not claim normalized coverage of every external rule.

## Adding checks

Register a stable ID and guidance in `android_audit/findings.py`. Call `context.check(...)` on both matched and unmatched analysis paths and on blocked inputs. Emit findings using the rule ID and identify a stable asset. Use explicit evidence references for anything other than the latest command result; `context.evidence_for(...)` retrieves command references by label. Do not place secret values into asset identities or finding details.
