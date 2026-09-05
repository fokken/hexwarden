CATEGORY = 'system_hardening'

def run(c):
    state = c.prop('ro.crypto.state')
    c.check('encryption_property', state in ('encrypted', 'unencrypted'))
    c.prop('ro.crypto.type')
    c.shell('sm list-volumes all', 'volumes')
    if state == 'unencrypted':
        c.finding('HW-ENC-001', 'ro.crypto.state=unencrypted; verify which volumes contain sensitive data.', 'high', 'high', evidence=c.evidence_for('ro.crypto.state'))
    c.note('Properties describe configuration, not cryptographic verification of each volume or credential-encrypted key protection.')
