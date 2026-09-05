CATEGORY = 'system_hardening'

def run(c):
    if c.setting('secure', 'install_non_market_apps') == '1':
        c.finding('Legacy unknown-source installation enabled', 'Legacy setting is enabled; modern Android uses per-app install permissions.', 'medium')
    value = c.shell(f'cmd appops query-op --user {c.args.user} REQUEST_INSTALL_PACKAGES allow', 'install_appops')
    if value and any('.' in line and 'No operations' not in line for line in value.splitlines()):
        c.finding('Apps allowed to request APK installation', 'Review packages in install_appops evidence; this is configuration, not proof of silent installation.', 'low')
    c.note('Review managed-device installation policies and OEM package installers separately.')
