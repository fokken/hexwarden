import json
import logging
import re
import shutil
import sys
from ..core import write_json
from ..bluetooth_host import fuzz_payloads

CATEGORY = 'wireless'


def parse_sdp(text):
    """Parse BlueZ's default browse output; preserve record association.

    Only explicit Channel/PSM fields inside protocol descriptors are used.
    Unknown output stays in raw evidence rather than becoming guessed endpoints.
    """
    records = []
    current = None
    protocol = None
    in_protocols = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith('Service Name:'):
            if current:
                records.append(current)
            current = {'name': stripped.split(':', 1)[1].strip(), 'endpoints': []}
            in_protocols, protocol = False, None
        elif stripped.startswith('Service RecHandle:'):
            if current and 'handle' in current:
                records.append(current)
                current = None
            current = current or {'name': None, 'endpoints': []}
            current['handle'] = stripped.split(':', 1)[1].strip()
        elif 'Protocol Descriptor List:' in stripped:
            current = current or {'name': None, 'endpoints': []}
            in_protocols, protocol = True, None
        elif in_protocols:
            match = re.match(r'"([^"]+)"\s+\(0x[0-9a-fA-F]+\)', stripped)
            if match:
                protocol = match[1].lower()
            else:
                match = re.fullmatch(r'(Channel|PSM):\s*(0x[0-9a-fA-F]+|[0-9]+)', stripped)
                if match:
                    label, value = match.groups()
                    number = int(value, 16 if value.startswith('0x') else 10)
                    if (protocol == 'rfcomm' and label == 'Channel' and 1 <= number <= 30) or (
                            protocol == 'l2cap' and label == 'PSM' and 1 <= number <= 65535 and number & 0x101 == 1):
                        endpoint = {'protocol': protocol, 'endpoint': number}
                        if endpoint not in current['endpoints']:
                            current['endpoints'].append(endpoint)
                elif stripped.endswith(':'):
                    in_protocols, protocol = False, None
    if current:
        records.append(current)
    return records


def worker(c, mode, extra=(), timeout=None):
    duration = timeout or c.args.bt_timeout
    value = c.command([sys.executable, '-m', 'android_audit.bluetooth_host', mode, c.args.bt_mac,
                       '--timeout', str(duration), *extra], 'host_' + mode, timeout=duration + 5)
    if value is None:
        return None
    try:
        result = json.loads(value)
        if not isinstance(result, dict):
            raise ValueError('expected object')
        return result
    except (ValueError, TypeError):
        c.note(f'{mode}: could not decode worker output; inspect raw evidence.')
        return None


def host_tests(c):
    mac = c.args.bt_mac
    if shutil.which('bluetoothctl') and sys.platform.startswith('linux'):
        c.command(['bluetoothctl', 'show'], 'host_adapter')
        c.command(['bluetoothctl', 'info', mac], 'host_target_before')
    if c.args.bt_mode in ('both', 'classic'):
        if sys.platform.startswith('linux') and shutil.which('sdptool'):
            value = c.command(['sdptool', 'browse', mac], 'host_sdp', timeout=c.args.bt_timeout)
            if value is not None:
                records = parse_sdp(value)
                c.check('sdp_service_parsing', bool(records), scope=mac, reason='No parseable service records.' if not records else None)
                path = c.directory / 'sdp-services.json'
                write_json(path, {'mac': mac, 'services': records})
                c.result['evidence'].append({'path': str(path.relative_to(c.root)), 'kind': 'derived'})
                if records:
                    c.finding('HW-BT-001', {'mac': mac, 'services': records}, 'info', 'high')
                else:
                    c.note('SDP produced no parseable service records; this is not proof of no services.')
                if c.args.bt_connect_classic:
                    endpoints = sorted({(e['protocol'], e['endpoint']) for r in records for e in r['endpoints']})
                    if len(endpoints) > 32:
                        c.note('Classic connection probes capped at 32 advertised endpoints.')
                    for protocol, endpoint in endpoints[:32]:
                        extra = ['--endpoint', str(endpoint)]
                        for payload in getattr(c.args, 'bt_classic_payload', []):
                            extra += ['--payload', payload]
                        result = worker(c, protocol, extra, timeout=min(c.args.bt_timeout, 5))
                        c.check('classic_connection_probe', bool(result) and result.get('status') == 'connected', scope={'mac': mac, 'protocol': protocol, 'endpoint': endpoint})
                        if result and result.get('status') == 'connected':
                            connection_detail = {key: value for key, value in result.items() if key != 'payloads'}
                            c.finding('HW-BT-002', connection_detail, 'info', 'high')
                            for payload in result.get('payloads', []):
                                if payload.get('status') == 'accepted':
                                    c.finding('HW-BT-006', {
                                        'mac': mac, 'protocol': protocol, 'endpoint': endpoint,
                                        'payload_length': payload['payload_length'],
                                        'payload_sha256': payload['payload_sha256'],
                                        'response_length': payload.get('response_length')}, 'info', 'high')
                        elif result:
                            c.note(f'{protocol} endpoint {endpoint}: connection failed or unavailable; inspect worker evidence, not proof of filtering/authentication.')
        else:
            c.note('Classic service discovery requires Linux and host sdptool (BlueZ tools).')
    if c.args.bt_mode in ('both', 'ble'):
        extra = (['--read'] if c.args.bt_read else []) + (['--pair'] if c.args.bt_pair else [])
        if getattr(c.args, 'bt_notify', False):
            extra += ['--notify', '--notify-seconds', str(getattr(c.args, 'bt_notify_seconds', 3))]
        write_plan_refs = []
        write_targets = getattr(c.args, 'bt_write_target', [])
        write_values = getattr(c.args, 'bt_write_payload', [])
        fuzz_enabled = getattr(c.args, 'bt_fuzz', False)
        if write_targets and (write_values or fuzz_enabled):
            payloads = [bytes.fromhex(value) for value in write_values]
            if fuzz_enabled:
                payloads.extend(fuzz_payloads(getattr(c.args, 'bt_fuzz_count', 16)))
            unique = []
            seen = set()
            for payload in payloads:
                if payload not in seen:
                    seen.add(payload)
                    unique.append(payload)
            unique = unique[:64]
            plan_path = c.directory / 'ble-write-probes.json'
            write_json(plan_path, {'mac': mac, 'targets': write_targets,
                                   'fuzz': fuzz_enabled,
                                   'payloads_hex': [payload.hex() for payload in unique]})
            plan_ref = {'path': str(plan_path.relative_to(c.root)), 'kind': 'write-plan'}
            c.result['evidence'].append(plan_ref)
            write_plan_refs = [plan_ref]
        for target in getattr(c.args, 'bt_write_target', []):
            extra += ['--write-target', target]
        for payload in getattr(c.args, 'bt_write_payload', []):
            extra += ['--write-payload', payload]
        if getattr(c.args, 'bt_fuzz', False):
            extra += ['--fuzz', '--fuzz-count', str(getattr(c.args, 'bt_fuzz_count', 16))]
        result = worker(c, 'ble', extra)
        c.check('ble_service_inspection', bool(result) and result.get('status') == 'collected', scope=mac)
        if result:
            for error in result.get('errors', []):
                c.note('BLE: ' + error)
            if result.get('status') != 'collected':
                c.note('BLE discovery/read coverage incomplete; inspect per-characteristic outcomes.')
            for service in result.get('services', []):
                for char in service['characteristics']:
                    detail = {'mac': mac, 'service_uuid': service['uuid'], 'characteristic_uuid': char['uuid'],
                              'handle': char['handle'], 'properties': char['properties']}
                    refs = [{**ref, 'locator': {'service_uuid': service['uuid'], 'characteristic_handle': char['handle']}} for ref in c.latest_evidence]
                    if char['advertises_write']:
                        c.finding('HW-BT-003', detail, 'info', 'high', evidence=refs)
                    if char.get('read', {}).get('status') == 'success':
                        c.finding('HW-BT-004',
                                  {**detail, 'bytes_read': char['read']['length']}, 'info', 'high', evidence=refs)
            for write in result.get('writes', []):
                detail = {'mac': mac, 'target': write['target'], 'service_uuid': write['service_uuid'],
                          'characteristic_uuid': write['characteristic_uuid'], 'handle': write['handle'],
                          'payload_length': write['payload_length'], 'payload_sha256': write['payload_sha256'],
                          'response': write['response'], 'advertises_write': write['advertises_write'],
                          'status': write['status']}
                refs = [{**ref, 'locator': {'target': write['target'], 'characteristic_handle': write['handle']}}
                        for ref in (c.latest_evidence + write_plan_refs)]
                logging.info('BLE write probe target=%s payload=%s status=%s',
                             write['target'], write.get('payload_hex', ''), write['status'])
                if write['status'] == 'accepted':
                    c.finding('HW-BT-005', detail, 'info', 'high', evidence=refs)
                else:
                    c.note(f"BLE write probe rejected for {write['target']}; this is evidence for the current host context only.")
            for notification in result.get('notifications', []):
                detail = {'mac': mac, 'service_uuid': notification['service_uuid'],
                          'characteristic_uuid': notification['characteristic_uuid'],
                          'handle': notification['handle'], 'status': notification['status'],
                          'event_count': len(notification.get('events', []))}
                if notification['status'] == 'subscribed':
                    c.finding('HW-BT-007', detail, 'info', 'high')
    if shutil.which('bluetoothctl') and sys.platform.startswith('linux'):
        c.command(['bluetoothctl', 'info', mac], 'host_target_after')
    c.note('Host tests use the default adapter and its existing bonds. Successful reads/connections do not prove unauthenticated access. GATT write flags are advertised capabilities; explicit write probes and bounded deterministic fuzzing require user-supplied targets and are limited to 64 payloads of 64 bytes or less. SDP may omit hidden/non-browsable endpoints. Target MAC is user-supplied and not verified against the ADB device; BLE privacy may require a different/current address.')


def run(c):
    c.shell('dumpsys bluetooth_manager', 'bluetooth_manager')
    c.shell('service list', 'binder_services')
    c.shell('ls -lZ /sys/class/bluetooth', 'bluetooth_sysfs')
    if c.args.bt_mac:
        host_tests(c)
    else:
        c.note('Local ADB inventory only. Set --bt-mac AA:BB:CC:DD:EE:FF for host SDP and BLE discovery; --bt-read and --bt-connect-classic enable additional access tests.')
