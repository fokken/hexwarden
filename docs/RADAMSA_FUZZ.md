# Radamsa socket fuzzing

[Back to README](../README.md)

Hexwarden can run a separate, explicitly targeted Radamsa campaign against a TCP
or UDP service. Review the `network` module's listener evidence first; the fuzzing
module never discovers or selects sockets automatically.

Install Radamsa using your distribution package, or build it from source if no
package is available:

```sh
sudo apt install radamsa
```

```sh
sudo apt install build-essential git
git clone https://gitlab.com/akihe/radamsa.git
cd radamsa
make
sudo make install
cd ..
radamsa --version
```

Then provide literal IP targets and one or more seed files:

```sh
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
crash correlation. By default, Hexwarden also starts an ADB `logcat` warning
stream during the campaign, collects the device crash buffer afterward, and
checks both for fatal signals, exceptions, ANRs, tombstones, and process-death
markers. These artifacts are stored as `crash-monitor.log`, `crash-buffer.txt`,
and their stderr output. Use `--radamsa-no-crash-monitor` only when the target is
not the connected Android device or when ADB monitoring is unsuitable.
`summary.json` records campaign totals and matched crash-indicator lines.

TCP opens a fresh connection for each payload and records up to 4096 response
bytes. UDP sends one datagram and waits for a response. A successful send or a
response is not a security finding; correlate the timestamped journal with
device logs, crash reports, ANR traces, and service health. Only fuzz services
you are authorized to test; payloads can change state or interrupt service.
