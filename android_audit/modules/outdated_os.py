CATEGORY = 'system_hardening'

from datetime import date

def patch_age(value, today):
    return (today - date.fromisoformat(value)).days

def run(c):
    for key in ('ro.build.version.release', 'ro.build.version.sdk', 'ro.build.fingerprint'):
        c.prop(key)
    for key in ('ro.build.version.security_patch', 'ro.vendor.build.security_patch'):
        value = c.prop(key)
        if value:
            try:
                age = patch_age(value, date.today())
                if age < 0:
                    c.note(f'{key}: patch date is in the future; verify device and host metadata.')
                elif age > c.args.patch_max_age:
                    c.finding('Security patch exceeds age policy', f'{key}={value}, {age} days old; threshold {c.args.patch_max_age} days.', 'high', 'high')
            except ValueError:
                c.note(f'{key}: invalid patch date {value!r}.')
    c.note('Patch properties are self-reported; age is a policy check, not a CVE or vendor-support assessment.')
