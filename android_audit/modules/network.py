"""Network inventory and conservative reachability review."""

import re

CATEGORY = 'networking'


def _endpoint_is_wildcard(endpoint):
    host = endpoint.rsplit(':', 1)[0].strip('[]') if ':' in endpoint else endpoint
    return host in ('0.0.0.0', '*', '::')


def parse_listeners(value):
    """Parse ss/netstat output without assuming process metadata is present."""
    listeners = []
    for line in value.splitlines():
        fields = line.split()
        if not fields or fields[0] not in ('tcp', 'tcp6', 'udp', 'udp6'):
            continue
        if len(fields) < 5:
            continue
        state, local, peer = fields[1], fields[4], fields[5] if len(fields) > 5 else ''
        if fields[0].startswith('tcp') and state.upper() != 'LISTEN':
            continue
        if fields[0].startswith('udp') and state.upper() not in ('UNCONN', 'LISTEN'):
            continue
        listeners.append({'protocol': fields[0], 'state': state, 'local': local,
                          'peer': peer, 'wildcard': _endpoint_is_wildcard(local),
                          'process': ' '.join(fields[6:]) if len(fields) > 6 else None})
    return listeners


def wildcard_listeners(value):
    return [listener for listener in parse_listeners(value) if listener['wildcard']]


def parse_processes(value):
    result = {}
    for line in value.splitlines():
        fields = line.split()
        if len(fields) < 2 or not fields[0].isdigit():
            continue
        pid = int(fields[0])
        uid = next((field.split('=', 1)[1] for field in fields if field.startswith('uid=')), None)
        if uid is None and len(fields) >= 3 and re.fullmatch(r'[A-Za-z0-9_.:-]+', fields[1]):
            uid = fields[1]
        result[pid] = {'pid': pid, 'uid': uid, 'name': fields[-1], 'raw': line}
    return result


def parse_package_uids(value):
    """Parse `pm list packages -U` rows into UID-to-package names."""
    mapping = {}
    for line in value.splitlines():
        match = re.search(r'package:([^\s]+)\s+uid:(\d+)', line)
        if match:
            mapping.setdefault(match[2], []).append(match[1])
    return mapping


def correlate_listeners(listeners, processes):
    correlated = []
    for listener in listeners:
        item = dict(listener)
        match = re.search(r'pid=(\d+)', listener.get('process') or '')
        item['pid'] = int(match.group(1)) if match else None
        item['process_identity'] = processes.get(item['pid']) if item['pid'] else None
        correlated.append(item)
    return correlated


def parse_interfaces(value):
    interfaces, current = [], None
    for line in value.splitlines():
        match = re.match(r'\d+:\s+([^:]+):\s+<([^>]*)>', line)
        if match:
            current = {'name': match[1], 'flags': match[2].split(','), 'addresses': []}
            interfaces.append(current)
        elif current:
            match = re.search(r'\binet6?\s+([^\s]+)', line)
            if match:
                current['addresses'].append(match[1])
    return interfaces


def parse_routes(value):
    routes = []
    for line in value.splitlines():
        fields = line.split()
        if not fields:
            continue
        route = {'raw': line, 'default': fields[0] == 'default'}
        for key in ('dev', 'via', 'metric'):
            if key in fields and fields.index(key) + 1 < len(fields):
                route[{'dev': 'interface', 'via': 'gateway', 'metric': 'metric'}[key]] = fields[fields.index(key) + 1]
        routes.append(route)
    return routes


def firewall_summary(value):
    policies = re.findall(r'(?im)^:([A-Za-z0-9_]+)\s+([A-Z]+)', value)
    rules = [line.strip() for line in value.splitlines() if line.strip().startswith('-A ')]
    return {'chains': [{'name': name, 'policy': policy} for name, policy in policies],
            'rule_count': len(rules), 'default_policies': {name: policy for name, policy in policies}}


def nftables_summary(value):
    """Summarize nftables base chains and verdicts without claiming packet reachability."""
    tables = re.findall(r'(?m)^\s*table\s+(\S+)\s+(\S+)\s*\{', value)
    chains = []
    for match in re.finditer(r'(?ms)^\s*chain\s+(\S+)\s*\{(.*?)(?=^\s*chain\s+|\Z)', value):
        name, body = match.groups()
        hook = re.search(r'(?m)^\s*type\s+\S+\s+hook\s+(\S+)\s+priority\s+([^;]+);', body)
        policy = re.search(r'\bpolicy\s+(\S+)\s*;', body)
        verdict_body = re.sub(r'\bpolicy\s+\S+\s*;', '', body)
        verdicts = re.findall(r'\b(accept|drop|reject|return|jump|goto)\b', verdict_body, re.I)
        interfaces = sorted(set(re.findall(r'\b(?:iifname|oifname)\s+["\']([^"\']+)["\']', body)))
        chains.append({'name': name, 'hook': hook.group(1) if hook else None,
                       'priority': hook.group(2).strip() if hook else None,
                       'policy': policy.group(1).lower() if policy else None,
                       'rule_count': max(0, len(body.strip().splitlines()) - (1 if hook else 0) - (1 if policy else 0)),
                       'verdicts': {verdict: sum(1 for item in verdicts if item.lower() == verdict) for verdict in sorted(set(item.lower() for item in verdicts))},
                       'interfaces': interfaces})
    return {'tables': [{'family': family, 'name': name} for family, name in tables],
            'chains': chains, 'rule_count': len([line for line in value.splitlines() if line.strip() and not line.strip().startswith(('table ', 'chain ', 'type ', 'policy ', '}'))])}


def namespace_summary(value):
    namespaces = []
    for line in value.splitlines():
        fields = line.split()
        if fields:
            namespaces.append({'name': fields[0], 'raw': line})
    return namespaces


def ebpf_summary(value):
    lines = [line.strip() for line in value.splitlines() if line.strip()]
    return {'line_count': len(lines),
            'program_count': sum(1 for line in lines if re.search(r'\b(prog|program)\b', line, re.I)),
            'link_count': sum(1 for line in lines if re.search(r'\blink\b', line, re.I)),
            'raw_available': bool(lines)}


def run(c):
    values = {}
    commands = (
        ('addresses', 'ip -details addr show'), ('links', 'ip -details link show'),
        ('routes4', 'ip -4 route show table all'), ('routes6', 'ip -6 route show table all'),
        ('rules4', 'ip -4 rule show'), ('rules6', 'ip -6 rule show'),
        ('listeners', 'ss -lntup'), ('unix_sockets', 'ss -lx'), ('processes', 'ps -A -o PID,UID,NAME'),
        ('package_uids', 'pm list packages -U'),
        ('connectivity', 'dumpsys connectivity'), ('wifi', 'dumpsys wifi'),
        ('tethering', 'dumpsys tethering'), ('ethernet', 'dumpsys ethernet'),
        ('network_namespaces', 'ip netns list'), ('pid_net_namespace', 'ls -l /proc/1/ns/net /proc/self/ns/net'),
        ('ipv4_forward', 'cat /proc/sys/net/ipv4/ip_forward'),
        ('ipv6_forward', 'cat /proc/sys/net/ipv6/conf/all/forwarding'))
    for label, command in commands:
        if label == 'listeners' and c.capabilities:
            available = c.capabilities['device']['commands']
            if available.get('ss') == 'unavailable' and available.get('netstat') == 'available':
                command = 'netstat -lntu'
                c.note('ss unavailable; listener evidence uses netstat without process attribution.')
        value = c.shell(command, label)
        values[label] = value
        if label == 'addresses':
            c.check('interface_inventory', bool(parse_interfaces(value or '')), scope='all interfaces')
        elif label.startswith('routes'):
            c.check('route_inventory', bool(parse_routes(value or '')), scope=label)
        elif label == 'processes':
            c.check('process_inventory', bool(parse_processes(value or '')))
        elif label == 'package_uids':
            c.check('package_uid_inventory', bool(parse_package_uids(value or '')))
        elif label == 'listeners':
            parsed = parse_listeners(value or '')
            recognized = bool(parsed) or bool(value and any(line.startswith(('Netid', 'Proto')) for line in value.splitlines()))
            c.check('listener_inventory', recognized, reason='No parseable listener rows.' if not recognized else None)
            correlated = correlate_listeners(parsed, parse_processes(values.get('processes') or ''))
            package_uids = parse_package_uids(values.get('package_uids') or '')
            for listener in correlated:
                identity = listener.get('process_identity')
                if identity and identity.get('uid') in package_uids:
                    identity['packages'] = package_uids[identity['uid']]
            if correlated:
                values['listeners_correlated'] = correlated
                wildcard = [listener for listener in correlated if listener['wildcard']]
                if wildcard:
                    c.finding('HW-NET-001', {'listeners': wildcard, 'process_identity_available': any(x['process_identity'] for x in wildcard)}, 'low', asset={'device': c.args.serial, 'listeners': [(x['protocol'], x['local']) for x in wildcard]})
        elif label in ('ipv4_forward', 'ipv6_forward'):
            c.check('ip_forwarding', value is not None and value.strip() in ('0', '1'), scope=label)
            if value and value.strip() == '1':
                c.finding('HW-NET-002', label + ': review expected routing/tethering role.', 'info', 'high', asset={'device': c.args.serial, 'stack': label})

    firewall = []
    for label, command in (('iptables', 'iptables-save'), ('ip6tables', 'ip6tables-save'), ('nftables', 'nft list ruleset')):
        value = c.shell(command, label, root=True)
        if value:
            summary = firewall_summary(value) if label != 'nftables' else nftables_summary(value)
            firewall.append({'family': label, **summary})
            policies = summary.get('default_policies') or {chain['name']: chain['policy'].upper() for chain in summary.get('chains', []) if chain.get('policy')}
            if policies and all(policy.upper() == 'ACCEPT' for policy in policies.values()):
                c.finding('HW-NET-004', {'family': label, 'summary': summary}, 'medium', 'medium', asset={'device': c.args.serial, 'family': label})
        c.check('firewall_policy', value is not None, scope=label, reason='Root/firewall command unavailable.' if value is None else None)
    for label, command in (('ebpf_network', 'bpftool net'), ('ebpf_programs', 'bpftool prog show')):
        value = c.shell(command, label, root=True)
        if value:
            values[label] = value
        c.check('ebpf_inventory', value is not None, scope=label, reason='Root/bpftool unavailable.' if value is None else None)
    if firewall:
        values['firewall_summary'] = firewall
    c.result['network_analysis'] = {'interfaces': parse_interfaces(values.get('addresses') or ''),
        'default_routes': [route for label in ('routes4', 'routes6') for route in parse_routes(values.get(label) or '') if route['default']],
        'listeners': values.get('listeners_correlated', []), 'firewall': firewall,
        'namespaces': namespace_summary(values.get('network_namespaces') or ''),
        'ebpf': {label: ebpf_summary(values.get(label) or '') for label in ('ebpf_network', 'ebpf_programs') if values.get(label)},
        'package_uids': parse_package_uids(values.get('package_uids') or '')}
    c.check('network_enforcement_context', bool(firewall or values.get('ebpf_network') or values.get('ebpf_programs') or values.get('network_namespaces')), reason='No firewall, eBPF or namespace enforcement evidence was available.')
    c.note('Socket process identity is best-effort and depends on ss permissions; netstat fallback has no PID attribution. Correlate wildcard listeners with default routes, interface addresses, tethering and firewall policy before treating exposure as reachable. Firewall summaries report configured chains and policies, not packet reachability. eBPF/offload paths, other namespaces and OEM projection roles may remain invisible.')
