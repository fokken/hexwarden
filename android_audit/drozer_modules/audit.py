"""Agent-context checks using Java reflection; no root or app impersonation."""
import json
from drozer.modules import Module


class Audit(Module):
    name = 'Hexwarden agent-context auditing'
    description = 'Report agent identity, effective package grants and bounded filesystem access.'
    author = 'Hexwarden'
    date = '2026-09-05'
    path = ['hexwarden']
    permissions = ['com.reversec.dz.permissions.GET_CONTEXT']

    def add_arguments(self, parser):
        parser.add_argument('--package', action='append', default=[])
        parser.add_argument('--list-path', action='append', default=[])
        parser.add_argument('--read-path', action='append', default=[])
        parser.add_argument('--write-dir', action='append', default=[])
        parser.add_argument('--entry-limit', type=int, default=50)

    def emit(self, kind, **values):
        self.stdout.write('HEXWARDEN_JSON ' + json.dumps(dict(kind=kind, **values)) + '\n')
        if hasattr(self.stdout, 'flush'):
            self.stdout.flush()

    def identity(self):
        context = self.getContext()
        identity = {'package': str(context.getPackageName()),
                    'uid': int(self.klass('android.os.Process').myUid()),
                    'pid': int(self.klass('android.os.Process').myPid()), 'selinux_context': None}
        identity['user_id'] = identity['uid'] // 100000
        try:
            gids = context.getPackageManager().getPackageInfo(identity['package'], 0x100).gids
            identity['package_gids'] = [int(gid) for gid in gids] if gids is not None else []
        except Exception as exc:
            identity['gids_error'] = str(exc)
        reader = None
        try:
            reader = self.new('java.io.BufferedReader', self.new('java.io.FileReader', '/proc/self/attr/current'))
            identity['selinux_context'] = str(reader.readLine())
        except Exception as exc:
            identity['selinux_error'] = str(exc)
        finally:
            if reader is not None:
                reader.close()
        return identity

    def package_grants(self, package):
        pm = self.getContext().getPackageManager()
        info = pm.getPackageInfo(package, 0x1000)
        entries = []
        if info.requestedPermissions is not None:
            for permission in info.requestedPermissions:
                permission = str(permission)
                grant = int(pm.checkPermission(permission, package))
                entries.append({'permission': permission, 'granted': grant == 0, 'result': grant})
        return {'package': package, 'uid': int(info.applicationInfo.uid), 'permissions': entries,
                'method': 'PackageManager.checkPermission', 'appops_verified': False}

    def filesystem(self, path, action, limit):
        result = {'path': path, 'action': action, 'status': 'unknown'}
        stream = None
        probe = None
        try:
            file = self.new('java.io.File', path)
            result['metadata'] = {'exists': file.exists() == True, 'is_file': file.isFile() == True,
                                  'is_directory': file.isDirectory() == True,
                                  'can_read': file.canRead() == True, 'can_write': file.canWrite() == True}
            if action == 'list':
                names = file.list()
                if names is None:
                    result['status'] = 'unavailable'
                    result['reason'] = 'Directory listing unavailable: denial, missing path, non-directory or I/O error.'
                else:
                    result['status'] = 'success'
                    result['entries'] = [str(name) for name in names][:limit]
                    result['truncated'] = len(names) > limit
            elif action == 'read':
                if file.isFile() != True:
                    result.update(status='unavailable', reason='Not a visible regular file; no special files opened.')
                else:
                    stream = self.new('java.io.FileInputStream', file)
                    value = int(stream.read())
                    result.update(status='success', bytes_read=0 if value == -1 else 1,
                                  content_retained=False)
            elif action == 'write':
                probe = self.klass('java.io.File').createTempFile('hexwarden-', '.probe', file)
                result['probe_path'] = str(probe.getAbsolutePath())
                self.emit('probe_created', path=result['probe_path'])
                stream = self.new('java.io.FileOutputStream', probe)
                stream.write(72)
                stream.close()
                stream = None
                result.update(status='success', bytes_written=1)
        except Exception as exc:
            result.update(status='failed', error=str(exc))
        finally:
            if stream is not None:
                try:
                    stream.close()
                except Exception as exc:
                    result['close_error'] = str(exc)
            if probe is not None:
                try:
                    result['cleanup_succeeded'] = probe.delete() == True
                except Exception as exc:
                    result.update(cleanup_succeeded=False, cleanup_error=str(exc))
        return result

    def execute(self, arguments):
        try:
            identity = self.identity()
            self.emit('identity', **identity)
        except Exception as exc:
            self.emit('error', stage='identity', error=str(exc))
            return
        packages = list(dict.fromkeys([identity['package'], *arguments.package]))
        for package in packages:
            try:
                self.emit('package_grants', **self.package_grants(package))
            except Exception as exc:
                self.emit('error', stage='package_grants', package=package, error=str(exc))
        for action, paths in (('list', arguments.list_path), ('read', arguments.read_path), ('write', arguments.write_dir)):
            for path in paths:
                self.emit('filesystem', **self.filesystem(path, action, max(1, min(arguments.entry_limit, 1000))))
        self.emit('complete')
