"""APK extraction and conservative manifest analysis shared by app modules."""
import hashlib
import re
import shlex
import shutil
from pathlib import Path
from .core import write_json

ANDROID = '{http://schemas.android.com/apk/res/android}'

def manifest_analysis(tree):
    app = tree.find('application')
    uses = tree.find('uses-sdk')
    target = uses.get(ANDROID + 'targetSdkVersion', '1') if uses is not None else '1'
    try:
        target = int(target)
    except ValueError:
        target = None
    result = {'package': tree.get('package'), 'target_sdk': target, 'components': [],
              'permissions': [], 'application': {}}
    for perm in tree.findall('permission'):
        protection = perm.get(ANDROID + 'protectionLevel', 'normal')
        try:
            base = int(protection, 0) & 15
            weak = base in (0, 1)
        except ValueError:
            weak = protection.split('|')[0] in ('normal', 'dangerous')
        result['permissions'].append({'name': perm.get(ANDROID + 'name'),
                                      'protection': protection, 'weak': weak})
    if app is None:
        return result
    result['application'] = {key: app.get(ANDROID + key) for key in
                             ('debuggable', 'allowBackup', 'usesCleartextTraffic', 'networkSecurityConfig', 'permission')}
    for tag in ('activity', 'activity-alias', 'service', 'receiver', 'provider'):
        for node in app.findall(tag):
            explicit = node.get(ANDROID + 'exported')
            if explicit in ('true', 'false'):
                exported = explicit == 'true'
            elif explicit is not None:
                exported = None
            elif tag == 'provider':
                exported = target < 17 if target is not None else None
            else:
                exported = node.find('intent-filter') is not None
            permission = node.get(ANDROID + 'permission', app.get(ANDROID + 'permission'))
            if tag == 'activity-alias' and permission is None:
                target_name = node.get(ANDROID + 'targetActivity')
                for activity in app.findall('activity'):
                    if activity.get(ANDROID + 'name') == target_name:
                        permission = activity.get(ANDROID + 'permission', app.get(ANDROID + 'permission'))
            read = node.get(ANDROID + 'readPermission', permission)
            write = node.get(ANDROID + 'writePermission', permission)
            unguarded = (not read or not write) if tag == 'provider' else not permission
            enabled = node.get(ANDROID + 'enabled', 'true') != 'false' and app.get(ANDROID + 'enabled', 'true') != 'false'
            result['components'].append({'type': tag, 'name': node.get(ANDROID + 'name'),
                'exported': exported, 'explicit_exported': explicit, 'enabled': enabled,
                'permission': permission, 'read_permission': read if tag == 'provider' else None,
                'write_permission': write if tag == 'provider' else None,
                'path_permissions': len(node.findall('path-permission')),
                'candidate_unguarded': exported is True and enabled and unguarded})
    return result


def collect_apps(c):
    if 'apps' in c.cache:
        cached = c.cache['apps']
        c.result['evidence'].extend(cached['evidence'])
        for limitation in cached['limitations']:
            c.note(limitation)
        return cached['apps']
    start = len(c.result['evidence'])
    apps = []
    try:
        from androguard.core.apk import APK
    except ImportError:
        APK = None
    if c.args.extract_apks and APK is None:
        c.note('Install the apps extra (androguard) for binary AndroidManifest.xml analysis.')
    for package, installed_path in c.packages():
        item = dict(package=package, installed_path=installed_path,
                    privileged_candidate='/priv-app/' in installed_path, apks=[], manifests=[])
        dump = c.shell('dumpsys package ' + shlex.quote(package), 'package_' + package)
        if dump and re.search(r'privateFlags=\[[^\]]*\bPRIVILEGED\b', dump):
            item['privileged_candidate'] = True
        if c.args.extract_apks:
            paths = c.shell('pm path ' + shlex.quote(package), 'paths_' + package) or ''
            directory = c.root / 'apks' / package
            directory.mkdir(parents=True, exist_ok=True)
            for index, line in enumerate(paths.splitlines()):
                if not line.startswith('package:/') or not line.endswith('.apk'):
                    continue
                remote = line[8:]
                destination = directory / f'{index:03d}.apk'
                value = c.command([c.args.adb, '-s', c.args.serial, 'pull', remote, str(destination)], 'pull_' + package)
                if value is None or not destination.is_file():
                    continue
                digest = hashlib.sha256()
                with destination.open('rb') as stream:
                    for block in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(block)
                item['apks'].append({'path': str(destination.relative_to(c.root)), 'remote': remote,
                                     'sha256': digest.hexdigest()})
                if shutil.which('apksigner'):
                    c.command(['apksigner', 'verify', '--verbose', '--print-certs', str(destination)], 'signature_' + package)
                else:
                    c.note('apksigner unavailable: cryptographic APK signature verification skipped.')
                if APK:
                    try:
                        apk = APK(str(destination))
                        manifest = manifest_analysis(apk.get_android_manifest_xml())
                        manifest['apk'] = str(destination.relative_to(c.root))
                        item['manifests'].append(manifest)
                        destination.with_suffix('.manifest.xml').write_bytes(apk.get_android_manifest_axml().get_xml())
                    except Exception as exc:
                        c.note(f'{package}: manifest analysis failed ({type(exc).__name__}).')
        apps.append(item)
    if not c.args.extract_apks:
        c.note('Enable --extract-apks for manifest-level analysis; dumpsys is retained but not treated as a complete manifest.')
    if not apps:
        c.note('No packages collected; inspect package visibility, filters and command failures.')
    write_json(c.directory / 'apps.json', apps)
    c.result['evidence'].append({'path': str((c.directory / 'apps.json').relative_to(c.root)), 'kind': 'derived'})
    c.cache['apps'] = {'apps': apps, 'evidence': c.result['evidence'][start:],
                       'limitations': list(c.result['limitations'])}
    return apps
