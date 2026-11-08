"""Root-invoked owner-delegation signer. NEVER reads Router.Cheap credentials."""
import base64,datetime,hashlib,json,os,pwd,re,stat,subprocess,sys
SIGNING_KEY='/home/nox/.config/awe/cloud4-authority-ed25519.pem'
def canonical(v): return json.dumps(v,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode('utf8')
def digest(v): return 'sha256:'+hashlib.sha256(canonical(v)).hexdigest()
def validate(d):
    ident=lambda v:isinstance(v,str) and re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}',v)
    if d.get('schema')!='awe.e1.cloud4.owner-authorization/1' or d.get('provenance')!='HOST_ATTESTED_CHAT_AND_GITHUB_DELEGATION' or d.get('owner_consent')!='ISSUED': raise ValueError()
    if d.get('provider')!='router.cheap' or d.get('budget_group_id')!='router.cheap.shared/1': raise ValueError()
    if not all(ident(d.get(k)) for k in ['key_binding_id','owner_id','issuer_id']): raise ValueError()
    if not isinstance(d.get('project_ids'),list) or not 1<=len(d['project_ids'])<=32 or len(set(d['project_ids']))!=len(d['project_ids']) or not all(ident(x) for x in d['project_ids']): raise ValueError()
    limits={'total_actual_micros':'10000000','account_reserve_unallocated_micros':'21000000','total_attempts':22,'canary':{'budget_micros':'500000','per_attempt_micros':'250000','attempts':2,'route_ids':['router.cheap.chat.gpt-6-sol','router.cheap.chat.claude-opus-4-8']},'followup':{'budget_micros':'9500000','per_attempt_micros':'1000000','attempts':20},'wire_attempts_per_request':1,'unknown_policy':'HOLD','fallback':'DENY','account_changes':'DENY'}
    if d.get('limits')!=limits or not re.fullmatch(r'sha256:[a-f0-9]{64}',d.get('mandate_digest','')): raise ValueError()
    if 'prior_authorization_digest' in d and (not re.fullmatch(r'sha256:[a-f0-9]{64}',d['prior_authorization_digest']) or type(d.get('scope_revision')) is not int or d['scope_revision']<2): raise ValueError()
    if d.get('evidence_mode') not in ['AUTHENTICATED_HOST','EXPLICIT_SYNTHETIC']: raise ValueError()
    if d['evidence_mode']=='EXPLICIT_SYNTHETIC':
        if not d['key_binding_id'].startswith('synthetic_') or not all(re.match(r'^prj_(cloud|qa3|qa4)_',p) for p in d['project_ids']): raise ValueError()
    elif d['key_binding_id'].startswith('synthetic_'): raise ValueError()
    issued=datetime.datetime.fromisoformat(d['issued_at'].replace('Z','+00:00'));expires=datetime.datetime.fromisoformat(d['expires_at'].replace('Z','+00:00'));now=datetime.datetime.now(datetime.timezone.utc)
    if not issued<=now<expires or (expires-issued).total_seconds()>86400: raise ValueError()
def protected_fd():
    if os.geteuid()!=pwd.getpwnam('nox').pw_uid: raise ValueError()
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in SIGNING_KEY.split('/')[1:-1]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory);os.close(directory);directory=child;s=os.fstat(directory)
            if s.st_uid not in (0,os.geteuid()) or s.st_mode&0o022: raise ValueError()
        fd=os.open(SIGNING_KEY.split('/')[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    finally: os.close(directory)
    s=os.fstat(fd)
    if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=os.geteuid() or s.st_nlink!=1 or not 32<=s.st_size<=4096: os.close(fd);raise ValueError()
    return fd
def validate_gate(d):
    if d.get('schema')!='awe.e1.cloud4.canary-gate/1' or d.get('provenance')!='HOST_ATTESTED_INDEPENDENT_CANARY_QA' or d.get('verdict')!='PASS': raise ValueError()
    if not all(re.fullmatch(r'[a-z][a-z0-9_.-]{0,79}',d.get(k,'')) for k in ['key_binding_id','evaluator_id']) or not re.fullmatch(r'sha256:[a-f0-9]{64}',d.get('authorization_digest','')): raise ValueError()
    ids=d.get('attempt_ids')
    if not isinstance(ids,list) or len(ids)!=2 or len(set(ids))!=2 or ids!=sorted(ids) or not all(re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}',x) for x in ids): raise ValueError()
    issued=datetime.datetime.fromisoformat(d['issued_at'].replace('Z','+00:00'));expires=datetime.datetime.fromisoformat(d['expires_at'].replace('Z','+00:00'));now=datetime.datetime.now(datetime.timezone.utc)
    if not issued<=now<expires or (expires-issued).total_seconds()>86400: raise ValueError()
def run():
    if sys.argv[1:]: raise ValueError()
    raw=sys.stdin.buffer.read(16385)
    if len(raw)>16384: raise ValueError()
    def unique(pairs):
        value={}
        for key,item in pairs:
            if key in value: raise ValueError()
            value[key]=item
        return value
    request=json.loads(raw,object_pairs_hook=unique);doc=request.get('document')
    if request.get('operation')=='sign-owner-authorization': validate(doc)
    elif request.get('operation')=='sign-canary-acceptance': validate_gate(doc)
    else: raise ValueError()
    if request.get('document_digest')!=digest(doc): raise ValueError()
    fd=protected_fd()
    try:
        path='/proc/self/fd/'+str(fd)
        def openssl(args,extra_fds=()):
            os.lseek(fd,0,os.SEEK_SET)
            result=subprocess.run(['/usr/bin/openssl']+args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,pass_fds=(fd,)+extra_fds,env={'PATH':'/usr/bin:/bin'},timeout=10,check=True)
            if len(result.stdout)>4096: raise ValueError()
            return result.stdout
        public=openssl(['pkey','-in',path,'-pubout','-outform','DER'])
        document_fd=os.memfd_create('cloud4-public-authorization',os.MFD_CLOEXEC)
        try:
            os.write(document_fd,canonical(doc));os.lseek(document_fd,0,os.SEEK_SET)
            signature=openssl(['pkeyutl','-sign','-rawin','-inkey',path,'-in','/proc/self/fd/'+str(document_fd)],(document_fd,))
        finally: os.close(document_fd)
        if len(signature)!=64: raise ValueError()
        encoded=base64.b64encode(public).decode('ascii')
        print(json.dumps({'schema':'awe.e1.cloud4.signed-receipt/1','algorithm':'Ed25519','document':doc,'document_digest':digest(doc),'public_key_spki_der':encoded,'public_key_digest':digest({'spki_der':encoded}),'signature':base64.b64encode(signature).decode('ascii')},separators=(',',':')))
    finally: os.close(fd)
if __name__=='__main__':
    try: run()
    except Exception:
        print('{"schema":"awe.e1.cloud4.signer-error/1","error":"CLOUD4_SIGNER_DENIED"}');sys.exit(1)
