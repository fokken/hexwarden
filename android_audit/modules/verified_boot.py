CATEGORY = 'system_hardening'

def run(c):
    values = {key: c.prop(key) for key in ('ro.boot.verifiedbootstate', 'ro.boot.flash.locked', 'ro.boot.vbmeta.device_state', 'ro.boot.veritymode', 'ro.build.tags')}
    known = {'ro.boot.verifiedbootstate': ('green', 'yellow', 'orange', 'red'),
             'ro.boot.flash.locked': ('0', '1'), 'ro.boot.vbmeta.device_state': ('locked', 'unlocked'),
             'ro.boot.veritymode': ('enforcing', 'eio', 'restart', 'logging', 'disabled')}
    for key, value in values.items():
        c.check('boot_property', value in known[key] if key in known else bool(value), scope=key, evidence=c.evidence_for(key))
    if values['ro.boot.flash.locked'] == '0' or values['ro.boot.vbmeta.device_state'] == 'unlocked':
        c.finding('HW-BOOT-001', 'Device properties indicate an unlocked bootloader.', 'high', 'high', evidence=c.evidence_for('ro.boot.flash.locked', 'ro.boot.vbmeta.device_state'))
    if values['ro.boot.verifiedbootstate'] in ('orange', 'red', 'yellow'):
        c.finding('HW-BOOT-002', 'Boot state: ' + values['ro.boot.verifiedbootstate'] + '. Yellow can indicate a user-configured root of trust.', 'medium', 'high', evidence=c.evidence_for('ro.boot.verifiedbootstate'))
    if values['ro.boot.veritymode'] in ('disabled', 'logging'):
        c.finding('HW-BOOT-003', 'Mode: ' + values['ro.boot.veritymode'], 'high', evidence=c.evidence_for('ro.boot.veritymode'))
    if values['ro.build.tags'] and 'test-keys' in values['ro.build.tags']:
        c.finding('HW-BOOT-004', 'Build tag is an indicator; verify actual signing certificates and AVB public keys.', 'medium', evidence=c.evidence_for('ro.build.tags'))
    c.note('Runtime properties can be forged on compromised devices. Green/locked does not establish a trusted production signing key or rollback protection.')
