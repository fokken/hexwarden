CATEGORY = 'system_hardening'

def run(c):
    for name in ('trust', 'device_policy', 'biometric', 'fingerprint', 'face'):
        c.shell('dumpsys ' + name, name)
    c.setting('secure', 'lock_screen_lock_after_timeout')
    c.note('Dumps are user/OEM dependent. Manually validate PIN/pattern/password strength, lock enforcement and enrolled biometrics; credential hashes are not collected.')
