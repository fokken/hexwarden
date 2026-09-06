"""Conservative preflight: absent is distinct from unverified/unknown."""
import importlib.metadata
import importlib.util
import re
import shlex
import shutil
import sys
from .core import write_json

DEVICE_TOOLS = ('id', 'getprop', 'settings', 'dumpsys', 'service', 'pm', 'cmd', 'sm', 'bmgr', 'ps',
                'logcat', 'ip', 'ss', 'netstat', 'cat', 'ls', 'find', 'getenforce', 'lshal',
                'timeout', 'tcpdump', 'su', 'iptables-save', 'ip6tables-save', 'nft', 'bpftool')


def command_probe():
    names = ' '.join(shlex.quote(name) for name in DEVICE_TOOLS)
    return ('for hw_tool in ' + names + '; do '
            'if command -v "$hw_tool" >/dev/null 2>&1; then '
            'printf "HW_CAP %s available\\n" "$hw_tool"; '
            'else printf "HW_CAP %s unavailable\\n" "$hw_tool"; fi; '
            'done; printf "HW_CAP_DONE\\n"')


def parse_commands(text):
    result = {name: 'unknown' for name in DEVICE_TOOLS}
    if text is None or 'HW_CAP_DONE' not in text.splitlines():
        return result
    for name, state in re.findall(r'^HW_CAP (\S+) (available|unavailable)$', text, re.M):
        if name in result:
            result[name] = state
    return result


def parse_services(text):
    if not text or 'Currently running services:' not in text:
        return {'status': 'unknown', 'names': []}
    tail = text.split('Currently running services:', 1)[1]
    names = [line.strip() for line in tail.splitlines() if line.strip()]
    if not names or any(not re.fullmatch(r'[A-Za-z0-9_.:/@-]+', name) for name in names):
        return {'status': 'unknown', 'names': []}
    return {'status': 'collected', 'names': sorted(set(names))}


def discover(c):
    evidence = c.start('capabilities', 'preflight')
    host = {}
    for executable in dict.fromkeys([c.args.adb, c.args.drozer_bin, c.args.emba, 'openssl', 'apksigner',
                                    'tshark', 'bluetoothctl', 'sdptool', 'radamsa', sys.executable]):
        path = shutil.which(executable)
        host[executable] = {'status': 'available' if path else 'unavailable', 'path': path}
    dependencies = {}
    for name in ('androguard', 'requests', 'bleak'):
        available = importlib.util.find_spec(name) is not None
        try:
            version = importlib.metadata.version(name) if available else None
        except importlib.metadata.PackageNotFoundError:
            version = None
        dependencies[name] = {'status': 'available' if available else 'unavailable', 'version': version}
    shell_id = c.shell('id', 'shell_identity')
    uid = re.search(r'\buid=(\d+)', shell_id or '')
    uid = int(uid.group(1)) if uid else None
    commands = parse_commands(c.shell(command_probe(), 'device_commands'))
    root = {'status': 'not_requested', 'method': None, 'commands': {}}
    if c.args.root:
        if uid == 0:
            root = {'status': 'available', 'method': 'adb_shell', 'commands': commands}
        else:
            value = c.shell('id', 'root_identity', root=True)
            match = re.search(r'\buid=(\d+)', value or '')
            if match and int(match.group(1)) == 0:
                root = {'status': 'available', 'method': 'su',
                        'commands': parse_commands(c.shell(command_probe(), 'root_commands', root=True))}
            else:
                root = {'status': 'unavailable', 'method': 'su', 'commands': {}}
                c.note('Existing su root access could not be established; privileged collectors will be skipped.')
    services = parse_services(c.shell('dumpsys -l', 'available_services'))
    data = {'host_tools': host, 'python_dependencies': dependencies,
            'device': {'shell_uid': uid, 'commands': commands, 'services': services, 'root': root,
                       'sdk': c.prop('ro.build.version.sdk'), 'release': c.prop('ro.build.version.release'),
                       'selected_user': c.args.user}, 'evidence': evidence}
    data['limits'] = ['Executable presence does not verify supported flags or access permissions.',
                      'Service lists reflect the ADB view at collection time; state may change.',
                      'Unknown capabilities are attempted, not treated as unavailable.']
    c.capabilities = data
    write_json(c.root / 'capabilities.json', data)
    return data
