"""Build and verify an overlay archive for the exact frozen base; no worktree mutations."""
import pathlib,json,hashlib,zipfile
root=pathlib.Path(__file__).resolve().parent.parent
directory=root/'RT-02'
imports=json.loads((directory/'import-manifest.json').read_text(encoding='utf-8'))
changes=json.loads((directory/'CHANGES.json').read_text(encoding='utf-8'))
paths={r['path'] for r in imports['rows']}|{r['path'] for r in changes['changes']}
paths|={'RT-02/before/'+r['path'] for r in imports['rows']}
paths|={str(p.relative_to(root)).replace('\\','/') for folder in ('sources','evidence') for p in (directory/folder).iterdir() if p.is_file()}
paths|={'RT-02/delta.patch','RT-02/CHANGES.json'}
rows=[{'path':p,'sha256':hashlib.sha256((root/p).read_bytes()).hexdigest()} for p in sorted(paths)]
manifest={'format':'RT02_EXACT_BASE_OVERLAY_V1','base_head':imports['base'],'rows':rows,'physical_decision':'DENY','real_hermes':'REAL_HERMES_NOT_RUN','production_ready':False}
mf=directory/'MANIFEST.json';mf.write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
delivery=directory/'delivery';delivery.mkdir(exist_ok=True)
archive=delivery/'AWE-GROUP-RT02-LOCAL-CANDIDATE.zip'
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as z:
    for p in sorted(paths|{'RT-02/MANIFEST.json'}): z.write(root/p,p)
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None
    assert set(z.namelist())==paths|{'RT-02/MANIFEST.json'}
    for r in rows: assert hashlib.sha256(z.read(r['path'])).hexdigest()==r['sha256']
result={'archive':str(archive),'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'manifest_sha256':hashlib.sha256(mf.read_bytes()).hexdigest(),'files':len(paths)+1,'archive_byte_readback':'PASS','base_included':False,'base_head':imports['base']}
(delivery/'DELIVERY.json').write_text(json.dumps(result,indent=2)+'\n',encoding='utf-8')
print(json.dumps(result))
