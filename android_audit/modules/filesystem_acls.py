CATEGORY = 'system_hardening'

def run(c):
    value = c.shell('getenforce', 'selinux')
    c.check('selinux_mode', value is not None and value.strip().lower() in ('enforcing', 'permissive', 'disabled'))
    if value and value.strip().lower() in ('permissive', 'disabled'):
        c.finding('HW-FS-001', value.strip(), 'high', 'high')
    c.shell('ls -ldZ /data /data/local /data/local/tmp /sdcard /system /vendor /data/misc /data/system', 'directory_permissions')
    value = c.shell('find /data/local /data/misc /data/system -xdev -type f -perm -0002 -print', 'world_writable', root=True)
    c.check('bounded_world_writable_files', value is not None)
    if value and value.strip():
        c.finding('HW-FS-002', 'Candidates found in bounded system data roots; correlate owner, SELinux labels and mount policy before assessing exploitability.', 'medium')
    c.shell('cat /proc/mounts', 'mounts')
    c.note('Bounded DAC inspection does not prove access by ordinary apps. SELinux, scoped storage, app UID, ACLs and mount namespaces require context-specific validation.')
