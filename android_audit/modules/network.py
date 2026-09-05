CATEGORY = 'networking'

import re

def wildcard_listeners(value):
    candidates = []
    for line in value.splitlines():
        fields = line.split()
        if len(fields) >= 6 and fields[0] in ('tcp', 'udp', 'tcp6', 'udp6'):
            local = fields[4]
            if re.match(r'^(?:0\.0\.0\.0|\*|\[::\]|::):', local):
                candidates.append({'protocol': fields[0], 'local': local})
    return candidates

def run(c):
    for label, command in (
        ('addresses', 'ip -details addr show'), ('links', 'ip -details link show'),
        ('routes4', 'ip -4 route show table all'), ('routes6', 'ip -6 route show table all'),
        ('rules4', 'ip -4 rule show'), ('rules6', 'ip -6 rule show'),
        ('listeners', 'ss -lntup'), ('unix_sockets', 'ss -lx'),
        ('connectivity', 'dumpsys connectivity'), ('wifi', 'dumpsys wifi'),
        ('tethering', 'dumpsys tethering'), ('ethernet', 'dumpsys ethernet'),
        ('ipv4_forward', 'cat /proc/sys/net/ipv4/ip_forward'),
        ('ipv6_forward', 'cat /proc/sys/net/ipv6/conf/all/forwarding')):
        if label == 'listeners' and c.capabilities:
            commands = c.capabilities['device']['commands']
            if commands.get('ss') == 'unavailable' and commands.get('netstat') == 'available':
                command = 'netstat -lntu'
                c.note('ss unavailable; listener evidence uses netstat without process attribution.')
        value = c.shell(command, label)
        if label == 'listeners':
            recognized = bool(value) and any(line.split() and line.split()[0] in ('Netid', 'tcp', 'tcp6', 'udp', 'udp6') for line in value.splitlines())
            c.check('wildcard_listener_heuristic', recognized and command.startswith('ss '),
                    reason='Requires ss output; fallback netstat is retained for manual review.' if not command.startswith('ss ') else None)
        if label in ('ipv4_forward', 'ipv6_forward'):
            c.check('ip_forwarding', value is not None and value.strip() in ('0', '1'), scope=label)
        if label == 'listeners' and value:
            listeners = wildcard_listeners(value)
            if listeners:
                c.finding('HW-NET-001', listeners, 'low')
        if label in ('ipv4_forward', 'ipv6_forward') and value and value.strip() == '1':
            c.finding('HW-NET-002', label + ': review expected routing/tethering role.', 'info', 'high', asset={'device': c.args.serial, 'stack': label})
    for label, command in (('iptables', 'iptables-save'), ('ip6tables', 'ip6tables-save'), ('nftables', 'nft list ruleset')):
        c.shell(command, label, root=True)
    c.note('Correlate AP/tethering/client roles in Wi-Fi and tethering dumps. Android Auto/vendor projection is not reliably identifiable as CarPlay. Socket visibility, eBPF policy and offloaded firewall paths may be restricted; listening does not prove remote reachability.')
