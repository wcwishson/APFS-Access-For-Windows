import argparse,ctypes as C,json,os,subprocess,threading,time,queue,shutil,hashlib
from ctypes import wintypes as W
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('--root',required=True);ap.add_argument('--tool',required=True);ap.add_argument('--fixture-builder',required=True);args=ap.parse_args()
root=Path(args.root).resolve();root.mkdir(parents=True,exist_ok=True);tool=str(Path(args.tool).resolve());builder=str(Path(args.fixture_builder).resolve())
assert all(p.drive.upper()=='D:' for p in [root,Path(tool),Path(builder)])
(root/'temp').mkdir(exist_ok=True)
os.environ['TMP']=os.environ['TEMP']=str(root/'temp')
k=C.WinDLL('kernel32',use_last_error=True)
k.CreateFileW.argtypes=[W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE];k.CreateFileW.restype=W.HANDLE
k.CloseHandle.argtypes=[W.HANDLE];k.CloseHandle.restype=W.BOOL
k.CreateEventW.argtypes=[C.c_void_p,W.BOOL,W.BOOL,W.LPCWSTR];k.CreateEventW.restype=W.HANDLE
k.SetEvent.argtypes=[W.HANDLE];k.SetEvent.restype=W.BOOL
k.MoveFileExW.argtypes=[W.LPCWSTR,W.LPCWSTR,W.DWORD];k.MoveFileExW.restype=W.BOOL
k.DeleteFileW.argtypes=[W.LPCWSTR];k.DeleteFileW.restype=W.BOOL
INVALID=C.c_void_p(-1).value
results=[];children=[];executions=[]
class Child:
 def __init__(self,cmd,handles=(),drain=True,stderr=None):
  si=subprocess.STARTUPINFO();si.lpAttributeList={'handle_list':list(handles)} if handles else {}
  self.p=subprocess.Popen(cmd,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=stderr if stderr is not None else subprocess.PIPE,startupinfo=si,close_fds=True)
  children.append(self.p);self.out=bytearray();self.err=bytearray();self.lines=queue.Queue();self.threads=[];self.overflow=False;self.start=time.monotonic();self.cmd=cmd;self.recorded=False
  def reader(stream,data,lines=False):
   pending=b''
   while True:
    chunk=os.read(stream.fileno(),4096)
    if not chunk:break
    if len(data)+len(chunk)>17*1024*1024:self.overflow=True;self.p.kill();break
    data.extend(chunk)
    if lines:
     pending+=chunk
     while b'\n' in pending:line,pending=pending.split(b'\n',1);self.lines.put(line)
  for stream,data,line in [(self.p.stdout,self.out,True)] if drain else []:
   t=threading.Thread(target=reader,args=(stream,data,line));t.start();self.threads.append(t)
  if self.p.stderr:
   t=threading.Thread(target=reader,args=(self.p.stderr,self.err));t.start();self.threads.append(t)
 def done(self,timeout=10):
  try:self.p.wait(timeout=timeout)
  except subprocess.TimeoutExpired:self.p.kill();self.p.wait(timeout=3);raise AssertionError('child exceeded deadline')
  for t in self.threads:t.join(3);assert not t.is_alive(),'pipe reader survived shutdown'
  assert self.p.poll() is not None and not self.overflow
  if not self.recorded:
   executions.append({'pid':self.p.pid,'command':self.cmd,'exit':self.p.returncode,'seconds':round(time.monotonic()-self.start,3),
    'stdoutBytes':len(self.out),'stderrBytes':len(self.err),'stdoutSha256':hashlib.sha256(self.out).hexdigest(),
    'stderr':self.err.decode(errors='replace')[:4096],'readersJoined':True})
   self.recorded=True
  if self.p.stdout:self.p.stdout.close()
  if self.p.stderr:self.p.stderr.close()
  return self.p.returncode,bytes(self.out),bytes(self.err)
def run(cmd,ok=True):
 r=Child(cmd).done();assert (r[0]==0)==ok,(r[0],r[1][:200],r[2]);return r

def case(name,body):
 start=time.monotonic();first=len(children)
 try:body();results.append({'name':name,'pass':True,'seconds':round(time.monotonic()-start,3)});print('PASS',name,flush=True)
 except Exception as e:results.append({'name':name,'pass':False,'error':str(e)});print('FAIL',name,str(e),flush=True)
 finally:
  for p in children[first:]:
   if p.poll() is None:p.kill();p.wait(timeout=3)

def export(kind='good',label=None):
 d=root/(label or kind);d.mkdir(exist_ok=True);run([builder,str(d),kind]);return d

def identities(d):
 return [json.loads(run([tool,'--mode','inspect','--image',str(d/n)])[1])['identity'] for n in ['main.img','tier2.img']]

def options(d,ids=None):
 ids=ids or identities(d)
 o={'--member-a':str(d/'main.img'),'--member-b':str(d/'tier2.img'),'--identity-a':ids[0],'--identity-b':ids[1],
 '--role-a':'main','--role-b':'tier2','--store-id-a':'apfs-store:main','--store-id-b':'apfs-store:tier2',
 '--store-offset-a':'0','--store-offset-b':'0','--store-size-a':str(64*4096),'--store-size-b':str(32*4096),
 '--container-uuid':'a'*32,'--fusion-uuid':'b'*31+'a','--checkpoint-xid':'20','--role-convention':'linux-apfs-last-byte-low-bit',
 '--volume-uuid':'c'*32,'--volume-oid':'101','--operation-timeout-ms':'5000'}
 return o

def command(o,mode='read',**changes):
 o=dict(o);o['--mode']=mode
 if mode in ['read','xattr']:o.update({'--inode':'30','--offset':'4093','--length':'8198'})
 if mode in ['enumerate','lookup']:o['--directory']='2'
 for key,value in changes.items():
  key='--'+key.replace('_','-')
  if value is None:o.pop(key,None)
  else:o[key]=str(value)
 cmd=[tool]+[v for kv in o.items() for v in kv]
 if mode in ['read','xattr']:cmd+=['--binary-stdout']
 return cmd

def read_eq(o,expected,mode='read',**kw):assert run(command(o,mode,**kw))[1]==expected

def file_handle(path,access=0x40000000,share=7):return k.CreateFileW(str(path),access,share,None,3,0,None)
def writable(path):
 h=file_handle(path);assert h!=INVALID,('writer not released',C.get_last_error());k.CloseHandle(h)
def denied(path,access):
 h=file_handle(path,access);err=C.get_last_error()
 if h!=INVALID:k.CloseHandle(h)
 assert h==INVALID and err==32,('expected sharing violation',h,err)
def ready_child(o,**kw):
 c=Child(command(o,'enumerate',repeat=3,interval_ms=800,**kw));line=c.lines.get(timeout=5);assert json.loads(line)['entries'];return c

def lease_test(o,d):
 c=ready_child(o)
 try:
  for n in ['main.img','tier2.img']:
   denied(d/n,0x40000000);denied(d/n,0x10000)
   assert not k.MoveFileExW(str(d/n),str(d/(n+'.moved')),0) and C.get_last_error()==32,'rename must fail with sharing violation'
   assert not k.DeleteFileW(str(d/n)) and C.get_last_error()==32,'delete must fail with sharing violation'
  rc,out,err=c.done();assert rc==0,err;assert len(out.splitlines())==3
  assert len(set(out.splitlines()))==1,'cached enumeration changed'
 finally:
  if c.p.poll() is None:c.p.kill();c.done()
 for n in ['main.img','tier2.img']:writable(d/n)

def substitute(d,o,member='main.img'):
 replacement=d/'replacement.img';shutil.copy2(d/member,replacement)
 old_hash=hashlib.sha256((d/member).read_bytes()).hexdigest();os.replace(replacement,d/member)
 assert hashlib.sha256((d/member).read_bytes()).hexdigest()==old_hash
 r=run(command(o),False);assert b'FusionImageIdentityChanged' in r[2] or b'Identity' in r[2],r
 for n in ['main.img','tier2.img']:writable(d/n)

def cancelled(o):
 event=k.CreateEventW(None,True,False,None);assert event;os.set_handle_inheritable(event,True)
 try:
  c=Child(command(o,'enumerate',repeat=64,interval_ms=100,cancel_handle=event),[event]);assert c.lines.get(timeout=5)
  assert k.SetEvent(event);rc,out,err=c.done(4);assert rc==6,(rc,err)
 finally:k.CloseHandle(event)

def fullpipe(o):
 c=Child(command(o,offset=0,length=16*1024*1024,operation_timeout_ms=250),drain=False)
 rc,out,err=c.done(4);assert rc in (6,8),(rc,err);assert time.monotonic()-c.start<3

def brokenpipe(o):
 c=Child(command(o,offset=0,length=16*1024*1024),drain=False);c.p.stdout.close();c.p.stdout=None
 rc,out,err=c.done(4);assert rc in (6,8),(rc,err)

def existing_writer(d,o):
 h=file_handle(d/'tier2.img');assert h!=INVALID
 try:run(command(o),False)
 finally:k.CloseHandle(h)
 for n in ['main.img','tier2.img']:writable(d/n)

def missing(d,o):
 os.rename(d/'tier2.img',d/'lost.img')
 try:run(command(o),False);writable(d/'main.img')
 finally:os.rename(d/'lost.img',d/'tier2.img')

def pre_cancel(d):
 event=k.CreateEventW(None,True,True,None);assert event;os.set_handle_inheritable(event,True)
 try:
  rc,out,err=Child([tool,'--mode','inspect','--image',str(d/'main.img'),'--cancel-handle',str(event)],[event]).done()
  assert rc==6 and not out,(rc,out,err)
 finally:k.CloseHandle(event)
 for n in ['main.img','tier2.img']:writable(d/n)

def blocked_leases(o,d,cancel=False):
 event=k.CreateEventW(None,True,False,None);assert event;os.set_handle_inheritable(event,True)
 try:
  c=Child(command(o,offset=0,length=16*1024*1024,operation_timeout_ms=1200,cancel_handle=event),[event],drain=False)
  assert os.read(c.p.stdout.fileno(),1)==b'\xa1'
  for n in ['main.img','tier2.img']:denied(d/n,0x40000000);denied(d/n,0x10000)
  if cancel:assert k.SetEvent(event)
  rc,out,err=c.done(4);assert rc==6,(rc,err)
 finally:k.CloseHandle(event)
 for n in ['main.img','tier2.img']:writable(d/n)

def full_stderr(o,d):
 reader,writer=os.pipe()
 try:
  os.write(writer,b'x'*4096)
  with os.fdopen(writer,'wb',buffering=0) as sink:
   writer=None
   c=Child(command(o,budget_reads=0,operation_timeout_ms=200),stderr=sink)
   rc,out,err=c.done(4);assert rc!=0 and not out,(rc,out)
 finally:
  os.close(reader)
  if writer is not None:os.close(writer)
 for n in ['main.img','tier2.img']:writable(d/n)

def duplicate_hardlink(d,o):
 link=d/'hardlink.img';os.link(d/'main.img',link)
 try:run(command(o,member_b=link,identity_b=o['--identity-a']),False)
 finally:link.unlink()
 for n in ['main.img','tier2.img']:writable(d/n)

def inspect_writer(d):
 for n in ['main.img','tier2.img']:
  h=file_handle(d/n);assert h!=INVALID
  try:run([tool,'--mode','inspect','--image',str(d/n)],False)
  finally:k.CloseHandle(h)
  writable(d/n)

def hashes(d):return {n:hashlib.sha256((d/n).read_bytes()).hexdigest() for n in ['main.img','tier2.img']}
def unchanged(d,expected):assert hashes(d)==expected,'member bytes changed'

def main():
 d=export();o=options(d);initial=hashes(d)
 case('usable help',lambda:run([tool,'--help']))
 case('production inspect identities',lambda: (len(identities(d))==2) or (_ for _ in ()).throw(AssertionError()))
 case('catalog two volumes narrow profile',lambda: catalog(o))
 case('cross-tier file bytes',lambda:read_eq(o,b'\xa1'*3+b'\xb1'*4096+b'\xa2'*4096+b'\xb2'*3))
 case('cross-tier resource fork',lambda:read_eq(o,b'XXXYYY','xattr',xattr='com.apple.ResourceFork',length=6))
 case('embedded xattr',lambda:read_eq(o,b'B'*32,'xattr',xattr='com.apple.FinderInfo',offset=0,length=32))
 case('sparse boundary',lambda:read_eq(o,b'\xb2'*2+b'\0'*4,offset=16382,length=6))
 case('EOF',lambda:read_eq(o,b'',offset=20480,length=1))
 case('zero length',lambda:read_eq(o,b'',offset=0,length=0))
 case('xattr EOF',lambda:read_eq(o,b'','xattr',xattr='com.apple.ResourceFork',offset=8192,length=8))
 case('xattr short EOF',lambda:read_eq(o,b'YY','xattr',xattr='com.apple.ResourceFork',offset=8190,length=8))
 case('unicode lookup',lambda:lookup(o))
 swapped=dict(o)
 for field in ['member','identity','role','store-id','store-offset','store-size']:swapped['--'+field+'-a'],swapped['--'+field+'-b']=o['--'+field+'-b'],o['--'+field+'-a']
 case('role tagged input reorder',lambda:read_eq(swapped,b'\xa1\xa1\xb1\xb1',offset=4094,length=4))
 case('held writer rename delete exclusion cached enumeration and release',lambda:lease_test(o,d))
 case('cancel after cached enumeration',lambda:cancelled(o))
 case('existing writer and failed bind cleanup',lambda:existing_writer(d,o))
 case('missing member cleanup',lambda:missing(d,o))
 case('same bytes replacement between inspect bind',lambda:substitute(d,o))
 o=options(d)
 case('tier2 same bytes replacement and first lease cleanup',lambda:substitute(d,o,'tier2.img'))
 o=options(d)
 case('pre-signaled cancellation refuses inspect',lambda:pre_cancel(d))
 case('inspect refuses existing writers',lambda:inspect_writer(d))
 case('hardlink duplicate identity refusal and cleanup',lambda:duplicate_hardlink(d,o))
 case('record budget',lambda:run(command(o,budget_records=0),False))
 case('missing inode',lambda:run(command(o,inode=9999),False))
 case('directory byte read refusal',lambda:run(command(o,inode=2),False))
 case('missing xattr',lambda:run(command(o,'xattr',xattr='missing'),False))
 case('missing directory',lambda:run(command(o,'enumerate',directory=9999),False))
 case('number overflow',lambda:run(command(o,length=2**64),False))
 case('identity empty selector',lambda:run(command(o,identity_a=''),False))
 for name,kw in [('wrong identity',{'identity_a':o['--identity-b']}),('wrong roles',{'role_a':'tier2','role_b':'main'}),('unknown role',{'role_a':'guess'}),('unknown convention',{'role_convention':'apple'}),('missing convention',{'role_convention':None}),('wrong container',{'container_uuid':'e'*32}),('wrong fusion UUID',{'fusion_uuid':'e'*32}),('wrong volume UUID',{'volume_uuid':'e'*32}),('wrong checkpoint',{'checkpoint_xid':21}),('zero checkpoint',{'checkpoint_xid':0}),('unknown source range',{'store_size_a':0}),('range overflow',{'store_offset_a':2**64-1}),('wrong exact size',{'store_size_a':4096}),('duplicate member',{'member_b':o['--member-a'],'identity_b':o['--identity-a']}),('duplicate store ID',{'store_id_b':o['--store-id-a']}),('missing member selector',{'member_b':None}),('read budget',{'budget_reads':0}),('byte budget',{'budget_bytes':1}),('material budget',{'budget_material':0}),('read bound',{'length':16*1024*1024+1}),('invalid number',{'length':'-1'}),('invalid event',{'cancel_handle':1})]:
  case(name,lambda kw=kw:run(command(o,**kw),False))
 for kind in ['unknown-feature','encrypted','bad-range','dirty-cache','nonempty-middle','unknown-volume-feature']:
  f=export(kind);fo=options(f);case(kind+' refusal',lambda fo=fo:run(command(fo),False))
 large=export('large-sparse');lo=options(large)
 case('full stdout pipe bounded failure',lambda:fullpipe(lo))
 case('broken stdout pipe failure',lambda:brokenpipe(lo))
 case('full stdout retains both leases until timeout then releases',lambda:blocked_leases(lo,large))
 case('cancel blocked stdout and release',lambda:blocked_leases(lo,large,True))
 case('full stderr bounded failure and cleanup',lambda:full_stderr(o,d))
 multi=export('multilevel');mo=options(multi)
 case('multilevel cross-tier metadata and content',lambda:read_eq(mo,b'\xa1'*3+b'\xb1'*4096+b'\xa2'*4096+b'\xb2'*3))
 case('multilevel enumeration 31 entries',lambda:count_entries(mo,31))
 case('second selected volume no fallback',lambda:run(command(o,volume_oid=102,volume_uuid='d'*32),False))
 for n in ['main.img','tier2.img']:case('final cleanup '+n,lambda n=n:writable(d/n))
 case('all original member bytes unchanged',lambda:unchanged(d,initial))

def catalog(o):
 obj=json.loads(run(command(o,'catalog'))[1]);assert not obj['generalFusionSupport'];assert [v['oid'] for v in obj['volumes']]==['101','102']
def lookup(o):assert json.loads(run(command(o,'lookup',name='Café.txt'))[1])['oid']=='30'
def count_entries(o,count):assert len(json.loads(run(command(o,'enumerate'))[1])['entries'])==count
try:main()
finally:
 for p in children:
  if p.poll() is None:p.kill();p.wait(timeout=3)
 report={'cases':len(results),'passed':sum(r['pass'] for r in results),'failed':sum(not r['pass'] for r in results),'children':len(children),'allChildrenExited':all(p.poll() is not None for p in children),'completedChildRecords':len(executions),'results':results}
 (root/'children.json').write_text(json.dumps(executions,indent=2))
 (root/'results.json').write_text(json.dumps(report,indent=2));print(json.dumps({k:v for k,v in report.items() if k!='results'}),flush=True)
raise SystemExit(0 if report['failed']==0 else 1)
