CATEGORY = 'system_hardening'

def run(c):
    state = c.prop('ro.crypto.state')
    c.prop('ro.crypto.type')
    c.shell('sm list-volumes all', 'volumes')
    if state == 'unencrypted':
        c.finding('Storage reports unencrypted', 'ro.crypto.state=unencrypted; verify which volumes contain sensitive data.', 'high', 'high')
    c.note('Properties describe configuration, not cryptographic verification of each volume or credential-encrypted key protection.')
