"""Host-only zero-generation discovery. Never emits credentials or raw bodies."""
import os, sys, stat, json, re, ssl, hashlib, datetime, decimal, urllib.request, urllib.error
ORIGIN = 'https://router.cheap'
SECRET = '/home/nox/.config/awe/router-cheap.key'
class DenyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.HTTPError(req.full_url,code,'REDIRECT_DENIED',headers,fp)
def read_secret():
    if os.geteuid() != __import__('pwd').getpwnam('nox').pw_uid: raise ValueError('HOST_IDENTITY')
    directory=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    try:
        for part in SECRET.split('/')[1:-1]:
            next_fd=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=directory)
            os.close(directory); directory=next_fd; s=os.fstat(directory)
            if s.st_uid not in (0,os.geteuid()) or s.st_mode & 0o022: raise ValueError('SECRET_PARENT_WRITABLE')
        fd=os.open(SECRET.split('/')[-1],os.O_RDONLY|os.O_NOFOLLOW,dir_fd=directory)
    finally: os.close(directory)
    try:
        s=os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or stat.S_IMODE(s.st_mode)!=0o600 or s.st_uid!=os.geteuid() or s.st_nlink!=1 or not 1<=s.st_size<=512: raise ValueError('SECRET_PERMISSIONS')
        key=os.read(fd,513).decode('ascii').strip()
        if not re.fullmatch(r'[A-Za-z0-9_.-]{16,512}',key): raise ValueError('SECRET_FORMAT')
        return key
    finally: os.close(fd)
def digest(b): return 'sha256:'+hashlib.sha256(b).hexdigest()
def number(v):
    if type(v) in (int,bool) or v is None: return v
    if isinstance(v,decimal.Decimal) and v.is_finite(): return str(v)
    return None
def scalar_dict(d,names): return {k:number(d[k]) for k in names if k in d and type(d[k]) in (int,bool,decimal.Decimal,type(None))}
def safe_id(v): return v if isinstance(v,str) and re.fullmatch(r'[A-Za-z0-9_.:/ -]{1,100}',v) else None
def request(path,key=None):
    # Neither URLs nor headers are taken from task/model input. Default TLS validates certificates.
    if path not in ['/v1/models','/v1/models/awe-e1-nonexistent-canary-model','/api/usage/token','/api/token/self','/v1/dashboard/billing/subscription','/v1/dashboard/billing/usage','/api/pricing','/api/status']: raise ValueError('PATH_DENIED')
    headers={'Accept':'application/json','User-Agent':'AWE-E1-Issue3-Preflight/1'}
    if key: headers['Authorization']='Bearer '+key
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),DenyRedirect(),urllib.request.HTTPSHandler(context=ssl.create_default_context()))
    try:
        with opener.open(urllib.request.Request(ORIGIN+path,headers=headers,method='GET'),timeout=20) as r:
            raw=r.read(4*1024*1024+1)
            if len(raw)>4*1024*1024: raise ValueError('BODY_BOUND')
            value=json.loads(raw,parse_float=decimal.Decimal)
            if not isinstance(value,dict): raise ValueError('BODY_SHAPE')
            return {'path':path,'status':r.status,'body_digest':digest(raw)},value
    except urllib.error.HTTPError as e: return {'path':path,'status':e.code,'raw_error_omitted':True},{}
def discover():
    key=read_secret(); observed=datetime.datetime.now(datetime.timezone.utc).isoformat()
    result={'schema':'awe.e1.router-cheap.preflight/1','observed_at':observed,'secret_custody':{'owner_verified':True,'mode':'0600','regular_single_link':True,'no_symlink_ancestors':True,'key_in_argv_env_or_output':False},'requests':[],'paid_generation_requests':0,'hard_actual_spend_limit':'UNVERIFIED','spending_enabled':False}
    for path in ['/v1/models','/api/usage/token','/api/token/self','/v1/dashboard/billing/subscription','/v1/dashboard/billing/usage','/api/pricing','/api/status']:
        row,data=request(path,key if path not in ['/api/pricing','/api/status'] else None)
        d=data.get('data',data)
        if path=='/v1/models' and isinstance(d,list):
            row['models']=[{'id':safe_id(x.get('id')),'field_names':sorted(k for k in x if re.fullmatch(r'[a-z_]{1,50}',k))} for x in d if isinstance(x,dict) and safe_id(x.get('id'))];row['model_count']=len(d)
        elif path=='/api/pricing':
            row['pricing_version']=safe_id(data.get('pricing_version'));row['models']=[]
            if isinstance(d,list):
                for model in d:
                    if not isinstance(model,dict): continue
                    m=scalar_dict(model,['model_ratio','completion_ratio','cache_ratio','create_cache_ratio','billing_multiplier','context_length','model_price','quota_type'])
                    m['model_id']=safe_id(model.get('model_name'));m['endpoint_types']=[safe_id(x) for x in model.get('supported_endpoint_types',[])];m['billing_mode']=safe_id(model.get('billing_mode'))
                    expr=model.get('billing_expr');m['billing_expression_digest']=digest(expr.encode()) if isinstance(expr,str) else None
                    m['billing_expression_support']='UNVERIFIED_NO_EVAL' if expr else 'NO_EXPRESSION'
                    row['models'].append(m)
            row['sources']=[]
            for src in data.get('routing_sources',[]):
                if not isinstance(src,dict): continue
                r=scalar_dict(src,['relative_price_numerator','relative_price_denominator','unit_price_numerator','unit_price_denominator'])
                r.update({k:safe_id(src.get(k)) for k in ['family','tier','status','label']});r['models']=[safe_id(x) for x in src.get('models',[])]
                r['model_factors']=[dict(scalar_dict(x,['price_multiplier','price_ratio']),model_id=safe_id(x.get('model'))) for x in src.get('model_discounts',[]) if isinstance(x,dict)]
                row['sources'].append(r)
            row['balance_metadata']=scalar_dict(data,['balance_unit_price_numerator','balance_unit_price_denominator'])
        elif isinstance(d,dict):
            row['numeric_fields']=scalar_dict(d,['quota_per_unit','usd_exchange_rate','remain_quota','used_quota','unlimited_quota','total_granted','total_used','total_available','total_usage','soft_limit_usd','hard_limit_usd','system_hard_limit_usd','access_until','expired_time','limit','usage','limit_remaining'])
            row['field_names']=[k for k in d if isinstance(k,str) and re.fullmatch(r'[A-Za-z_]{1,80}',k)]
            if path=='/api/status': row['field_names']=['quota_per_unit','usd_exchange_rate']
        result['requests'].append(row)
    # Single metadata-only negatives. No generation endpoint is allowed.
    for path,auth in [('/v1/models',None),('/v1/models/awe-e1-nonexistent-canary-model',key)]:
        row,_=request(path,auth);row['check']='NO_AUTH_METADATA' if auth is None else 'INVALID_MODEL_METADATA';result['requests'].append(row)
    encoded=json.dumps(result,ensure_ascii=True,separators=(',',':'))
    if key in encoded: raise ValueError('SECRET_OUTPUT_GUARD')
    sys.stdout.write(encoded+'\n')
if __name__=='__main__':
    try:
        if sys.argv[1:]!=['preflight']: raise ValueError('PREFLIGHT_ONLY_NO_PAID_TRANSPORT')
        discover()
    except Exception as exc:
        # No exception messages, request headers/bodies, file contents or tracebacks.
        code=exc.args[0] if type(exc) is ValueError and exc.args and exc.args[0] in ['HOST_IDENTITY','SECRET_PATH_LINK','SECRET_PARENT_WRITABLE','SECRET_PERMISSIONS','SECRET_FORMAT','REDIRECT_DENIED','BODY_BOUND','BODY_SHAPE','PATH_DENIED','SECRET_OUTPUT_GUARD','PREFLIGHT_ONLY_NO_PAID_TRANSPORT'] else 'READ_OR_NETWORK_FAILURE'
        sys.stdout.write(json.dumps({'schema':'awe.e1.router-cheap.preflight/1','status':'BLOCKED_HOST_PREFLIGHT','reason':code,'paid_generation_requests':0,'spending_enabled':False})+'\n')
        sys.exit(1)
