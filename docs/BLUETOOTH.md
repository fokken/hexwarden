# Bluetooth testing

[Back to README](../README.md) · [Linux installation](../README.md#installation-linux)

Supply the remote device's MAC to enable host-side testing in addition to the ADB Bluetooth inventory:

```sh
python3 -m pip install -e '.[bluetooth]'
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
