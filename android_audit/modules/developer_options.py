CATEGORY = 'system_hardening'

def run(c):
    for key in ('development_settings_enabled', 'adb_enabled', 'adb_wifi_enabled'):
        value = c.setting('global', key)
        if value == '1':
            c.finding(key + ' enabled', 'Debugging increases local or network attack surface. USB ADB is expected during this audit.', 'low', 'high')
    for key in ('service.adb.tcp.port', 'persist.adb.tcp.port'):
        value = c.prop(key)
        if value and value.isdigit() and int(value) > 0:
            c.finding('Network ADB configured', f'{key}={value}; verify listening socket, authentication and reachability.', 'medium')
    c.prop('ro.adb.secure')
