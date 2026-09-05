CATEGORY = 'system_hardening'

def run(c):
    for key in ('development_settings_enabled', 'adb_enabled', 'adb_wifi_enabled'):
        value = c.setting('global', key)
        c.check('developer_setting', value in ('0', '1'), scope=key)
        if value == '1':
            c.finding('HW-DEV-001', 'Debugging increases local or network attack surface. USB ADB is expected during this audit.', 'low', 'high', asset={'device': c.args.serial, 'setting': key, 'user': c.args.user})
    for key in ('service.adb.tcp.port', 'persist.adb.tcp.port'):
        value = c.prop(key)
        c.check('network_adb_port', value is not None and value.lstrip('-').isdigit(), scope=key)
        if value and value.isdigit() and int(value) > 0:
            c.finding('HW-DEV-002', f'{key}={value}; verify listening socket, authentication and reachability.', 'medium', asset={'device': c.args.serial, 'property': key})
    c.prop('ro.adb.secure')
