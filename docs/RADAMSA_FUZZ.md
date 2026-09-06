# Radamsa socket fuzzing

[Back to README](../README.md)

Hexwarden can run a separate, explicitly targeted Radamsa campaign against a TCP
or UDP service. Review the `network` module's listener evidence first; the fuzzing
module never discovers or selects sockets automatically.

Install Radamsa using your distribution package, then provide literal IP targets
and one or more seed files:

```sh
sudo apt install radamsa
hexwarden scan --radamsa-fuzz \
  --radamsa-target 192.0.2.10:9000 \
  --radamsa-protocol tcp \
  --radamsa-seed-file seeds/request.bin \
  --radamsa-count 100 --radamsa-timeout 3 --radamsa-delay-ms 50 \
  --radamsa-max-seconds 1800
```

IPv6 targets use `[ADDR]:PORT`. Multiple targets and seed files can be supplied.
The default campaign is 100 iterations per target, with a three-second Radamsa
and socket timeout. Payloads are capped at 4 KiB by default and the CLI caps a
campaign at 10,000 iterations, 1 MiB payloads, and 1,800 seconds by default.

Every generated payload is journaled before it is sent and again after the send
attempt in `evidence/radamsa_fuzz/radamsa-fuzz.jsonl`. Records include UTC
timestamps, sequence number, target, protocol, seed file, payload hex, length,
SHA-256, send status, response length, and errors. The journal is flushed and
fsynced per record so the last prepared payload remains available after a target
or test process crash. Exact payloads are also written to the audit log for
crash correlation. `summary.json` records campaign totals.

TCP opens a fresh connection for each payload and records up to 4096 response
bytes. UDP sends one datagram and waits for a response. A successful send or a
response is not a security finding; correlate the timestamped journal with
device logs, crash reports, ANR traces, and service health. Only fuzz services
you are authorized to test; payloads can change state or interrupt service.
