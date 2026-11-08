import sys,json,difflib,pathlib
root=pathlib.Path(__file__).resolve().parent.parent
rows=json.loads((root/'RT-02/CHANGES.json').read_text(encoding='utf-8'))['changes']
result=[]
for row in rows:
    path=row['path']
    before=root/'RT-02/before'/path
    old=before.read_text(encoding='utf-8') if row['before_sha256'] else ''
    new=(root/path).read_text(encoding='utf-8')
    result.append('diff --git a/'+path+' b/'+path+'\n')
    if not row['before_sha256']: result.append('new file mode 100644\n')
    result.extend(difflib.unified_diff(old.splitlines(True),new.splitlines(True),fromfile='a/'+path if row['before_sha256'] else '/dev/null',tofile='b/'+path))
(root/'RT-02/delta.patch').write_bytes(''.join(result).encode('utf-8'))
