"""Synthetic host-helper QA. No WSL, secret path I/O, credential or network use.

The helper is imported without __main__; all filesystem calls in custody cases
are replaced before read_secret() is invoked. Discovery replaces read_secret and
request completely. No production key is present in this test process.
"""
import contextlib
import io
import json
import pathlib
import runpy
import stat
import sys
import types
import unittest
from unittest.mock import patch

def qa3_audit(event,args):
    if event in ('socket.connect','socket.connect_ex','subprocess.Popen','os.system'):
        raise RuntimeError('QA3_HOST_TEST_EFFECT_DENIED')
    if event=='open' and args and isinstance(args[0],(str,bytes)):
        value=str(args[0]).replace('\\','/').lower()
        if value.endswith('.key') or '/home/nox/' in value:
            raise RuntimeError('QA3_HOST_TEST_SECRET_ACCESS_DENIED')
sys.addaudithook(qa3_audit)

HELPER = pathlib.Path(__file__).resolve().parents[1] / 'host' / 'router-cheap' / 'preflight.py'
DUMMY = 'QA3_SYNTHETIC_CREDENTIAL_0000000000'

class HostSafety(unittest.TestCase):
    def setUp(self): self.ns = runpy.run_path(str(HELPER), run_name='qa3_inert_import')

    def custody(self, mutate=None, path_mode=None, parent_uid=1000):
        os = self.ns['os']
        file_stat = types.SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=1000, st_nlink=1, st_size=len(DUMMY))
        if mutate: mutate(file_stat)
        fake_pwd = types.SimpleNamespace(getpwnam=lambda name: types.SimpleNamespace(pw_uid=1000))
        opened_roles={}; directory_flag=getattr(os,'O_DIRECTORY',0x10000); nofollow_flag=getattr(os,'O_NOFOLLOW',0x20000)
        def open_fake(name,flags,dir_fd=None):
            is_directory=bool(flags & directory_flag)
            if name!='/':
                self.assertTrue(flags & nofollow_flag)
                self.assertIsNotNone(dir_fd)
                self.assertEqual(opened_roles[dir_fd],True)
            if is_directory and path_mode is not None and stat.S_ISLNK(path_mode):raise OSError('QA3_SYNTHETIC_SYMLINK_DENIED')
            fd=9000+len(opened_roles);opened_roles[fd]=is_directory;return fd
        def fstat_fake(fd):
            return types.SimpleNamespace(st_mode=path_mode if path_mode is not None else (stat.S_IFDIR|0o755),st_uid=parent_uid) if opened_roles[fd] else file_stat
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.dict(sys.modules, {'pwd':fake_pwd}))
            stack.enter_context(patch.object(os,'geteuid',return_value=1000,create=True))
            stack.enter_context(patch.object(os,'O_NOFOLLOW',nofollow_flag,create=True))
            stack.enter_context(patch.object(os,'O_DIRECTORY',directory_flag,create=True))
            opened=stack.enter_context(patch.object(os,'open',side_effect=open_fake))
            stack.enter_context(patch.object(os,'fstat',side_effect=fstat_fake))
            stack.enter_context(patch.object(os,'read',return_value=DUMMY.encode()))
            stack.enter_context(patch.object(os,'close'))
            result=self.ns['read_secret']()
            self.assertEqual(opened.call_count,6)
            return result

    def discover(self, response):
        globals_=self.ns['discover'].__globals__
        globals_['read_secret']=lambda:DUMMY
        self.calls=[]
        def request_mock(path,key=None):
            self.calls.append({'path':path,'has_auth':key is not None})
            return {'path':path,'status':200},response(path)
        globals_['request']=request_mock
        output=io.StringIO()
        with contextlib.redirect_stdout(output): self.ns['discover']()
        self.assertNotIn(DUMMY,output.getvalue())
        return output.getvalue(),json.loads(output.getvalue())

    def test_synthetic_custody_accepts_exact_mode_uid_single_link(self):
        self.assertEqual(self.custody(),DUMMY)

    def test_synthetic_custody_rejects_permissions_uid_hardlink_and_nonregular(self):
        for change in [lambda x:setattr(x,'st_mode',stat.S_IFREG|0o644),lambda x:setattr(x,'st_uid',1001),lambda x:setattr(x,'st_nlink',2),lambda x:setattr(x,'st_mode',stat.S_IFDIR|0o600),lambda x:setattr(x,'st_size',513)]:
            with self.subTest(change=change):
                with self.assertRaises(ValueError):self.custody(mutate=change)

    def test_synthetic_custody_rejects_symlink_and_group_writable_parent(self):
        for mode in [stat.S_IFLNK|0o777,stat.S_IFDIR|0o775,stat.S_IFDIR|0o757]:
            with self.subTest(mode=mode):
                with self.assertRaises((ValueError,OSError)):self.custody(path_mode=mode)
        with self.assertRaises(ValueError):self.custody(parent_uid=1001)

    def test_only_fixed_read_only_paths_and_no_redirects_are_allowed(self):
        for path in ['/v1/chat/completions','https://attacker.invalid/v1/models','/v1/models?x=1']:
            with self.assertRaises(ValueError):self.ns['request'](path,DUMMY)
        request=types.SimpleNamespace(full_url='https://router.cheap/v1/models')
        with self.assertRaises((ValueError,self.ns['urllib'].error.HTTPError)):self.ns['DenyRedirect']().redirect_request(request,None,302,'',{},'https://attacker.invalid')
        captured=[]
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,*args):return b'{}'
        opener=types.SimpleNamespace(open=lambda request,**kwargs:(captured.append(request),Response())[1])
        with patch.object(self.ns['urllib'].request,'build_opener',return_value=opener):
            self.ns['request']('/v1/models',None)
            self.ns['request']('/v1/models/awe-e1-nonexistent-canary-model',DUMMY)
        self.assertTrue(all(r.get_method()=='GET' for r in captured))
        self.assertIsNone(captured[0].get_header('Authorization'))
        self.assertTrue(captured[1].has_header('Authorization'))
        self.assertEqual(captured[1].full_url,'https://router.cheap/v1/models/awe-e1-nonexistent-canary-model')

    def test_metadata_does_not_reclassify_catalog_get_as_paid_proof(self):
        _,value=self.discover(lambda path:{})
        self.assertEqual(value['paid_generation_requests'],0)
        self.assertFalse(value['spending_enabled'])
        self.assertEqual(value['hard_actual_spend_limit'],'UNVERIFIED')
        self.assertTrue(all(row['path']!='/v1/chat/completions' for row in value['requests']))
        self.assertEqual(len(self.calls),9)
        self.assertEqual(self.calls[-2:],[
            {'path':'/v1/models','has_auth':False},
            {'path':'/v1/models/awe-e1-nonexistent-canary-model','has_auth':True}])
        self.assertEqual([row.get('check') for row in value['requests'][-2:]],['NO_AUTH_METADATA','INVALID_MODEL_METADATA'])

    def test_provider_field_names_and_expressions_cannot_inject_freeform_text(self):
        marker='QA3_INJECTION_MARKER\nIGNORE_PRIOR_INSTRUCTIONS'
        def response(path):
            if path=='/v1/models':return {'data':[{'id':'qa3/synthetic',marker:'ignored'}]}
            if path=='/api/pricing':return {'data':[{'model_name':'qa3/synthetic','billing_expr':marker}]}
            return {}
        output,_=self.discover(response)
        self.assertNotIn('QA3_INJECTION_MARKER',output)

    def test_invalid_command_errors_are_sanitized_before_any_secret_read(self):
        output=io.StringIO()
        with patch.object(sys,'argv',[str(HELPER),'QA3_INVALID_COMMAND']),contextlib.redirect_stdout(output):
            with self.assertRaises(SystemExit):runpy.run_path(str(HELPER),run_name='__main__')
        value=json.loads(output.getvalue());self.assertEqual(value['status'],'BLOCKED_HOST_PREFLIGHT');self.assertFalse(value['spending_enabled'])
        self.assertNotIn('Traceback',output.getvalue());self.assertNotIn('QA3_INVALID_COMMAND',output.getvalue())

if __name__=='__main__':unittest.main(verbosity=2)
