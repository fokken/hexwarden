CATEGORY = 'system_hardening'

def run(c):
    for key in ('ro.build.ab_update', 'ro.virtual_ab.enabled', 'ro.boot.slot_suffix', 'ro.build.version.incremental'):
        c.prop(key)
    c.shell('dumpsys update_engine', 'update_engine')
    c.shell('dumpsys system_update', 'system_update')
    c.shell('ls -lZ /system/etc/security/otacerts.zip', 'ota_certificates')
    c.note('OTA signature enforcement, rollback behavior and endpoint security require firmware/update packages and vendor documentation. APK signatures are checked by app_extraction when apksigner is installed. Play Integrity enforcement requires application/backend review and cannot be inferred from installed Google services.')
