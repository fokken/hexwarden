"""Isolated host-side Bluetooth probes, invoked by the Bluetooth audit module.

Uses the host's default adapter and current bonding/security state. Write probes
are opt-in, target-scoped, deterministic, and bounded; a successful operation
is evidence for the current host context, not proof of an unauthenticated bypass.
"""
import argparse
import asyncio
import json
import hashlib
import socket
import sys
from datetime import datetime, timezone


def connect_classic(mac, protocol, endpoint, timeout, payloads=(), socket_factory=None):
    result = {'mac': mac, 'protocol': protocol, 'endpoint': endpoint,
              'status': 'error', 'payload_sent': False, 'payloads': []}
    if not sys.platform.startswith('linux') or not hasattr(socket, 'AF_BLUETOOTH'):
        result['error'] = 'Classic socket probes require Linux Bluetooth socket support.'
        return result
    factory = socket_factory or socket.socket
    kind, proto = ((socket.SOCK_STREAM, socket.BTPROTO_RFCOMM) if protocol == 'rfcomm'
                   else (socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP))
    try:
        with factory(socket.AF_BLUETOOTH, kind, proto) as connection:
            connection.settimeout(timeout)
            connection.connect((mac, endpoint))
            result['status'] = 'connected'
            for payload in payloads:
                attempt = {'payload_hex': payload.hex(), 'payload_length': len(payload),
                           'payload_sha256': hashlib.sha256(payload).hexdigest(), 'status': 'pending'}
                try:
                    connection.sendall(payload)
                    attempt['status'] = 'accepted'
                    result['payload_sent'] = True
                    try:
                        attempt['response_length'] = len(connection.recv(4096))
                    except socket.timeout:
                        attempt['response_length'] = None
                except OSError as exc:
                    attempt.update(status='rejected', error_type=type(exc).__name__, error=str(exc))
                result['payloads'].append(attempt)
    except OSError as exc:
        result.update(status='failed', error_type=type(exc).__name__,
                      errno=exc.errno, error=str(exc))
    return result


def fuzz_payloads(count):
    """Return small deterministic payloads suitable for authorization probes."""
    seeds = [b'\x00', b'\xff', b'\x01', b'\x00\xff', b'\xff\x00',
             b'\x00' * 4, bytes(range(4)), b'\x00' * 16, b'\xff' * 16,
             bytes(range(32)), b'\x00' * 64, b'\xff' * 64]
    limit = max(0, min(int(count), 64))
    while len(seeds) < limit:
        length = min(64, 1 << (len(seeds) % 7))
        seeds.append(bytes((index + len(seeds)) & 0xff for index in range(length)))
    return seeds[:limit]


async def enumerate_ble(mac, timeout, read=False, pair=False, scanner=None, client_factory=None,
                        write_targets=(), write_payloads=(), fuzz=False, fuzz_count=16,
                        notify=False, notify_seconds=3):
    result = {'mac': mac, 'status': 'partial', 'pair_requested': pair,
              'read_requested': read, 'notify_requested': notify, 'services': [], 'writes': [],
              'notifications': [], 'errors': [],
              'security_context': 'Host may have existing bonds; link authentication/encryption not independently measured.'}
    if scanner is None or client_factory is None:
        try:
            from bleak import BleakClient, BleakScanner
        except ImportError:
            result['errors'].append('Install the bluetooth extra (bleak) for host BLE testing.')
            return result
        scanner, client_factory = BleakScanner, BleakClient

    async def probe():
        device = await scanner.find_device_by_address(mac, timeout=timeout)
        if device is None:
            result['errors'].append('Target not observed in BLE advertisements; may be asleep, classic-only, or using a different/private address.')
            return
        result['device'] = {'address': device.address, 'name': device.name}
        async with client_factory(device, timeout=timeout, pair=pair) as client:
            result['connected'] = bool(client.is_connected)
            notification_chars = []
            target_map = {}
            for target in write_targets:
                parts = target.split('/', 1)
                if len(parts) == 2:
                    target_map[(parts[0].lower(), parts[1].lower())] = target
            for service in client.services:
                entry = {'uuid': service.uuid, 'handle': service.handle, 'characteristics': []}
                result['services'].append(entry)
                for char in service.characteristics:
                    props = list(char.properties)
                    characteristic = {'uuid': char.uuid, 'handle': char.handle, 'properties': props,
                        'advertises_write': bool({'write', 'write-without-response', 'authenticated-signed-writes'} & set(props)),
                        'descriptors': [{'uuid': d.uuid, 'handle': d.handle} for d in char.descriptors]}
                    entry['characteristics'].append(characteristic)
                    if notify and ({'notify', 'indicate'} & set(props)):
                        notification_chars.append((service, char, characteristic))
                    target = target_map.get((str(service.uuid).lower(), str(char.uuid).lower()))
                    if target:
                        target_map.pop((str(service.uuid).lower(), str(char.uuid).lower()), None)
                        payloads = [bytes.fromhex(value) for value in write_payloads]
                        if fuzz:
                            payloads.extend(fuzz_payloads(fuzz_count))
                        seen = set()
                        payloads = [payload for payload in payloads
                                    if not (payload in seen or seen.add(payload))][:64]
                        # Prefer acknowledged writes where supported; otherwise use the
                        # write-without-response form advertised by the characteristic.
                        response = 'write' in props or 'authenticated-signed-writes' in props
                        for payload in payloads:
                            attempt = {'target': target, 'service_uuid': service.uuid,
                                       'characteristic_uuid': char.uuid, 'handle': char.handle,
                                       'payload_hex': payload.hex(),
                                       'payload_length': len(payload),
                                       'payload_sha256': hashlib.sha256(payload).hexdigest(),
                                       'advertises_write': characteristic['advertises_write'],
                                       'response': response, 'status': 'pending'}
                            try:
                                await asyncio.wait_for(client.write_gatt_char(char, payload, response=response), min(timeout, 5))
                                attempt['status'] = 'accepted'
                            except Exception as exc:
                                attempt.update(status='rejected', error_type=type(exc).__name__, error=str(exc))
                            result['writes'].append(attempt)
                    if read and 'read' in props:
                        characteristic['read'] = {'status': 'pending'}
                        try:
                            value = await asyncio.wait_for(client.read_gatt_char(char), min(timeout, 5))
                            # Values remain only in restricted raw evidence, not findings.
                            characteristic['read'] = {'status': 'success', 'length': len(value), 'hex': bytes(value).hex()}
                        except Exception as exc:
                            characteristic['read'] = {'status': 'failed', 'error_type': type(exc).__name__, 'error': str(exc)}
            if notify and notification_chars:
                for service, char, characteristic in notification_chars:
                    events = []
                    dropped = [0]
                    def callback(sender, data, events=events, dropped=dropped, service=service, char=char):
                        if len(events) >= 256:
                            dropped[0] += 1
                            return
                        value = bytes(data)
                        events.append({'timestamp': datetime.now(timezone.utc).isoformat(timespec='milliseconds'),
                                       'service_uuid': service.uuid, 'characteristic_uuid': char.uuid,
                                       'handle': char.handle, 'length': len(value), 'hex': value[:4096].hex(),
                                       'truncated': len(value) > 4096})
                    notification = {'service_uuid': service.uuid, 'characteristic_uuid': char.uuid,
                                    'handle': char.handle, 'status': 'pending', 'events': events,
                                    'dropped_events': dropped}
                    try:
                        await asyncio.wait_for(client.start_notify(char, callback), min(timeout, 5))
                        notification['status'] = 'subscribed'
                    except Exception as exc:
                        notification.update(status='failed', error_type=type(exc).__name__, error=str(exc))
                    result['notifications'].append(notification)
                if any(item['status'] == 'subscribed' for item in result['notifications']):
                    await asyncio.sleep(min(notify_seconds, max(0.1, timeout / 2)))
                for item, (_, char, _) in zip(result['notifications'], notification_chars):
                    if item['status'] == 'subscribed':
                        try:
                            await asyncio.wait_for(client.stop_notify(char), min(timeout, 5))
                        except Exception as exc:
                            item.update(status='partial', error_type=type(exc).__name__, error=str(exc))
                    item['dropped_events'] = item['dropped_events'][0]
            for target in target_map.values():
                result['errors'].append(f'Write target not found in discovered services: {target}')
            result['status'] = 'collected'
            if target_map:
                result['status'] = 'partial'
            if any(ch.get('read', {}).get('status') == 'failed' for s in result['services'] for ch in s['characteristics']):
                result['status'] = 'partial'
            if any(item.get('status') in ('failed', 'partial') for item in result['notifications']):
                result['status'] = 'partial'

    try:
        await asyncio.wait_for(probe(), timeout=timeout)
    except Exception as exc:
        result['errors'].append(f'{type(exc).__name__}: {exc}')
        result['status'] = 'partial'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('ble', 'rfcomm', 'l2cap'))
    parser.add_argument('mac')
    parser.add_argument('--timeout', type=float, default=30)
    parser.add_argument('--endpoint', type=int)
    parser.add_argument('--read', action='store_true')
    parser.add_argument('--pair', action='store_true')
    parser.add_argument('--payload', action='append', default=[])
    parser.add_argument('--write-target', action='append', default=[])
    parser.add_argument('--write-payload', action='append', default=[])
    parser.add_argument('--fuzz', action='store_true')
    parser.add_argument('--fuzz-count', type=int, default=16)
    parser.add_argument('--notify', action='store_true')
    parser.add_argument('--notify-seconds', type=float, default=3)
    args = parser.parse_args(argv)
    if args.mode == 'ble':
        if sys.platform == 'darwin':
            result = {'status': 'partial', 'services': [], 'errors': ['macOS BLE uses OS identifiers, not Bluetooth MAC addresses; use Linux or Windows for this MAC-targeted collector.']}
        else:
            result = asyncio.run(enumerate_ble(args.mac, args.timeout, args.read, args.pair,
                                               write_targets=args.write_target,
                                               write_payloads=args.write_payload,
                                               fuzz=args.fuzz, fuzz_count=args.fuzz_count,
                                               notify=args.notify, notify_seconds=args.notify_seconds))
    else:
        result = connect_classic(args.mac, args.mode, args.endpoint, args.timeout,
                                 payloads=[bytes.fromhex(value) for value in args.payload])
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
