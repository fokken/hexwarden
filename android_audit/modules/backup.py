CATEGORY = 'system_hardening'

def run(c):
    c.shell('bmgr enabled', 'backup_manager')
    c.shell('dumpsys backup', 'backup')
    c.setting('secure', 'backup_enabled')
    c.note('Backup manager enabled does not prove adb backup availability. Android version, app target SDK, debuggable/allowBackup and OEM policy affect eligibility. Review extracted manifests; no backup is initiated.')
