"""Narrow pure score-function executor; no provider keys or host files mounted."""
import ast,hashlib,json,os,resource,subprocess,sys,tempfile

def denied(code):
    print(json.dumps({'status':'DENIED','reason':code,'sandbox_enforced':False}));sys.exit(1)

def validate_source(code):
    if not isinstance(code,str) or not 1<=len(code.encode())<=4096: raise ValueError('SOURCE_BOUND')
    tree=ast.parse(code)
    if len(tree.body)!=1 or not isinstance(tree.body[0],ast.FunctionDef): raise ValueError('ONE_FUNCTION_REQUIRED')
    f=tree.body[0]
    if f.name!='score' or f.decorator_list or f.returns or len(f.args.args)!=1 or f.args.args[0].arg!='skills' or f.args.args[0].annotation or f.args.defaults or f.args.kw_defaults or f.args.kwonlyargs or f.args.posonlyargs or f.args.vararg or f.args.kwarg: raise ValueError('SCORE_SIGNATURE')
    allowed=(ast.Module,ast.FunctionDef,ast.arguments,ast.arg,ast.Return,ast.Assign,ast.Name,ast.Load,ast.Store,ast.Dict,ast.Constant,ast.List,ast.Tuple,ast.Set,ast.For,ast.If,ast.Compare,ast.Eq,ast.NotEq,ast.In,ast.NotIn,ast.Add,ast.BinOp,ast.AugAssign,ast.Call,ast.Attribute,ast.GeneratorExp,ast.SetComp,ast.ListComp,ast.comprehension,ast.IfExp,ast.UnaryOp,ast.Not,ast.And,ast.Or,ast.BoolOp,ast.Subscript,ast.Expr)
    nodes=list(ast.walk(tree))
    if len(nodes)>240: raise ValueError('AST_BOUND')
    safe_builtins={'set','sum','str','list','tuple','len'}
    forbidden={'eval','exec','open','globals','locals','compile','input','getattr','setattr','delattr','vars','dir','type','object','super','help','breakpoint','print','score'}
    if sum(isinstance(n,ast.FunctionDef) for n in nodes)!=1: raise ValueError('NESTED_FUNCTION_DENIED')
    declared={'skills'}|{n.id for n in nodes if isinstance(n,ast.Name) and isinstance(n.ctx,ast.Store)}
    for n in nodes:
        if not isinstance(n,allowed): raise ValueError('AST_NODE_DENIED')
        if isinstance(n,ast.Name):
            if n.id.startswith('_') or not n.id.isidentifier() or n.id in forbidden: raise ValueError('NAME_DENIED')
            if isinstance(n.ctx,ast.Store) and n.id in safe_builtins: raise ValueError('BUILTIN_REBIND_DENIED')
            if isinstance(n.ctx,ast.Load) and n.id not in declared|safe_builtins: raise ValueError('UNRESOLVED_NAME_DENIED')
        if isinstance(n,ast.Attribute) and n.attr not in ['strip','lower','casefold','get']: raise ValueError('ATTRIBUTE_DENIED')
        if isinstance(n,ast.Call):
            if n.keywords or not (isinstance(n.func,ast.Name) and n.func.id in ['set','sum','str','list','tuple','len'] or isinstance(n.func,ast.Attribute) and n.func.attr in ['strip','lower','casefold','get']): raise ValueError('CALL_DENIED')
        if isinstance(n,ast.Constant) and not (type(n.value) in [str,int,bool,type(None)] and (not isinstance(n.value,str) or len(n.value)<=80) and (type(n.value)!=int or abs(n.value)<=100)): raise ValueError('CONSTANT_DENIED')
    return tree

DRIVER="""import json,sys,os,socket
from score_helper import score
rows=json.load(sys.stdin)
result=[]
for skills in rows:
    before=list(skills); value=score(skills)
    if type(value) is not int or not 0<=value<=10 or skills!=before: raise ValueError('SCORE_RESULT')
    result.append(value)
sock=socket.socket();sock.settimeout(.1)
network_denied=sock.connect_ex(('127.0.0.1',11434))!=0;sock.close()
print(json.dumps({'scores':result,'boundary':{'home_absent':not os.path.exists('/home'),'windows_absent':not os.path.exists('/mnt/c'),'repository_absent':not os.path.exists('/repo'),'host_network_denied':network_denied}}))
"""

def run():
    if sys.argv[1:]: denied('NO_ARGUMENTS')
    raw=sys.stdin.buffer.read(16385)
    if len(raw)>16384: denied('REQUEST_BOUND')
    request=json.loads(raw)
    if set(request)!=set(['code','inputs']): denied('REQUEST_SCHEMA')
    code=request['code'];validate_source(code);rows=request['inputs']
    if not isinstance(rows,list) or not 1<=len(rows)<=64 or any(not isinstance(x,list) or len(x)>32 or any(not isinstance(s,str) or len(s)>40 for s in x) for x in rows): denied('INPUT_BOUND')
    def limits():
        resource.setrlimit(resource.RLIMIT_CPU,(3,3));resource.setrlimit(resource.RLIMIT_AS,(536870912,536870912));resource.setrlimit(resource.RLIMIT_FSIZE,(1048576,1048576));resource.setrlimit(resource.RLIMIT_NOFILE,(64,64));resource.setrlimit(resource.RLIMIT_NPROC,(64,64))
    with tempfile.TemporaryDirectory(prefix='awe-score-') as folder:
        os.chmod(folder,0o700)
        candidate=folder+'/score_helper.py';driver=folder+'/runner.py'
        with open(candidate,'w') as f:f.write(code)
        with open(driver,'w') as f:f.write(DRIVER)
        cmd=['/usr/bin/bwrap','--unshare-all','--new-session','--die-with-parent','--cap-drop','ALL','--clearenv','--setenv','PATH','/usr/bin:/bin','--ro-bind','/usr','/usr','--ro-bind','/lib','/lib','--ro-bind','/lib64','/lib64','--proc','/proc','--dev','/dev','--tmpfs','/tmp','--dir','/work','--ro-bind',candidate,'/work/score_helper.py','--ro-bind',driver,'/work/runner.py','--chdir','/work','--','/usr/bin/python3','-B','-S','/work/runner.py']
        result=subprocess.run(cmd,input=json.dumps(rows).encode(),stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,timeout=8,preexec_fn=limits,env={'PATH':'/usr/bin:/bin'})
        if result.returncode or len(result.stdout)>65536: denied('SANDBOX_EXECUTION_FAILED')
        output=json.loads(result.stdout)
        if not all(output.get('boundary',{}).get(k) is True for k in ['home_absent','windows_absent','repository_absent','host_network_denied']): denied('SANDBOX_BOUNDARY_FAILED')
        print(json.dumps({'schema':'awe.recruit.score-sandbox/1','status':'EXECUTED','source_digest':'sha256:'+hashlib.sha256(code.encode()).hexdigest(),'scores':output['scores'],'boundary':output['boundary'],'sandbox_enforced':True,'network':'DENY','limits':{'cpu_seconds':3,'address_space_bytes':536870912,'file_bytes':1048576,'open_fds':64,'processes':64,'wall_seconds':8},'external_effects':0},separators=(',',':')))

if __name__=='__main__':
    try:run()
    except Exception:denied('SANDBOX_DENIED')
