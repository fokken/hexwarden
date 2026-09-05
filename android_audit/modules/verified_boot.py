CATEGORY = 'system_hardening'

def run(c):
    values = {key: c.prop(key) for key in ('ro.boot.verifiedbootstate', 'ro.boot.flash.locked', 'ro.boot.vbmeta.device_state', 'ro.boot.veritymode', 'ro.build.tags')}
    if values['ro.boot.flash.locked'] == '0' or values['ro.boot.vbmeta.device_state'] == 'unlocked':
        c.finding('Bootloader reports unlocked', 'Device properties indicate an unlocked bootloader.', 'high', 'high')
    if values['ro.boot.verifiedbootstate'] in ('orange', 'red', 'yellow'):
        c.finding('Verified boot requires review', 'Boot state: ' + values['ro.boot.verifiedbootstate'] + '. Yellow can indicate a user-configured root of trust.', 'medium', 'high')
    if values['ro.boot.veritymode'] in ('disabled', 'logging'):
        c.finding('dm-verity enforcement requires review', 'Mode: ' + values['ro.boot.veritymode'], 'high')
    if values['ro.build.tags'] and 'test-keys' in values['ro.build.tags']:
        c.finding('Build tagged test-keys', 'Build tag is an indicator; verify actual signing certificates and AVB public keys.', 'medium')
    c.note('Runtime properties can be forged on compromised devices. Green/locked does not establish a trusted production signing key or rollback protection.')
