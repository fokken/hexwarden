CATEGORY = 'system_hardening'

def run(c):
    legacy = c.setting('secure', 'install_non_market_apps')
    c.check('legacy_unknown_sources', legacy in ('0', '1'))
    if legacy == '1':
        c.finding('HW-INSTALL-001', 'Legacy setting is enabled; modern Android uses per-app install permissions.', 'medium')
    value = c.shell(f'cmd appops query-op --user {c.args.user} REQUEST_INSTALL_PACKAGES allow', 'install_appops')
    c.check('installer_appops_heuristic', value is not None)
    if value and any('.' in line and 'No operations' not in line for line in value.splitlines()):
        c.finding('HW-INSTALL-002', 'Review packages in install_appops evidence; this is configuration, not proof of silent installation.', 'low')
    c.note('Review managed-device installation policies and OEM package installers separately.')
