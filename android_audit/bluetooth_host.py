"""Isolated host-side Bluetooth probes, invoked by the Bluetooth audit module.

Uses the host's default adapter and current bonding/security state. This worker
never sends application writes; a successful connection is not an auth bypass.
"""
import argparse
import asyncio
import json
import socket
import sys


def connect_classic(mac, protocol, endpoint, timeout, socket_factory=None):
    result = {'mac': mac, 'protocol': protocol, 'endpoint': endpoint,
              'status': 'error', 'payload_sent': False}
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
    except OSError as exc:
        result.update(status='failed', error_type=type(exc).__name__,
                      errno=exc.errno, error=str(exc))
    return result


async def enumerate_ble(mac, timeout, read=False, pair=False, scanner=None, client_factory=None):
    result = {'mac': mac, 'status': 'partial', 'pair_requested': pair,
              'read_requested': read, 'services': [], 'errors': [],
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
            for service in client.services:
                entry = {'uuid': service.uuid, 'handle': service.handle, 'characteristics': []}
                result['services'].append(entry)
                for char in service.characteristics:
                    props = list(char.properties)
                    characteristic = {'uuid': char.uuid, 'handle': char.handle, 'properties': props,
                        'advertises_write': bool({'write', 'write-without-response', 'authenticated-signed-writes'} & set(props)),
                        'descriptors': [{'uuid': d.uuid, 'handle': d.handle} for d in char.descriptors]}
                    entry['characteristics'].append(characteristic)
                    if read and 'read' in props:
                        characteristic['read'] = {'status': 'pending'}
                        try:
                            value = await asyncio.wait_for(client.read_gatt_char(char), min(timeout, 5))
                            # Values remain only in restricted raw evidence, not findings.
                            characteristic['read'] = {'status': 'success', 'length': len(value), 'hex': bytes(value).hex()}
                        except Exception as exc:
                            characteristic['read'] = {'status': 'failed', 'error_type': type(exc).__name__, 'error': str(exc)}
            result['status'] = 'collected'
            if any(ch.get('read', {}).get('status') == 'failed' for s in result['services'] for ch in s['characteristics']):
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
    args = parser.parse_args(argv)
    if args.mode == 'ble':
        if sys.platform == 'darwin':
            result = {'status': 'partial', 'services': [], 'errors': ['macOS BLE uses OS identifiers, not Bluetooth MAC addresses; use Linux or Windows for this MAC-targeted collector.']}
        else:
            result = asyncio.run(enumerate_ble(args.mac, args.timeout, args.read, args.pair))
    else:
        result = connect_classic(args.mac, args.mode, args.endpoint, args.timeout)
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
