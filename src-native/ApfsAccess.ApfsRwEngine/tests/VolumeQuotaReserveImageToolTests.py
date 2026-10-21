"""Focused private real-image command gates. No mounts or physical devices."""
import argparse, ctypes, hashlib, json, os, pathlib, stat, subprocess, sys, time

p=argparse.ArgumentParser();p.add_argument('--root',required=True);p.add_argument('--tool',required=True);p.add_argument('--fixtures',required=True)
p.add_argument('--production-only',action='store_true')
p.add_argument('--capture-self-test',action='store_true')
a=p.parse_args();root=pathlib.Path(a.root).resolve();assert root.drive.upper()=='D:'
root.mkdir(parents=True,exist_ok=False);(root/'temp').mkdir();env=dict(os.environ,TEMP=str(root/'temp'),TMP=str(root/'temp'))
output=root/'process-output';output.mkdir()
rows=[]
def run(args,ok=True,expect_json=False):
    command=[str(x) for x in args];tag=f'{len(rows):04d}'
    stdout_file=output/f'{tag}.stdout.bin';stderr_file=output/f'{tag}.stderr.bin'
    started=time.monotonic();timed_out=False
    with stdout_file.open('wb') as stdout,stderr_file.open('wb') as stderr:
        process=subprocess.Popen(command,cwd=root,env=env,stdout=stdout,stderr=stderr)
        try:process.wait(timeout=60)
        except subprocess.TimeoutExpired:
            timed_out=True;process.kill();process.wait(timeout=10)
    stdout_bytes=stdout_file.read_bytes();stderr_bytes=stderr_file.read_bytes()
    result=subprocess.CompletedProcess(command,process.returncode,stdout_bytes.decode('utf-8').replace('\r\n','\n'),stderr_bytes.decode('utf-8').replace('\r\n','\n'))
    row=dict(command=command,pid=process.pid,elapsed_seconds=time.monotonic()-started,exit=result.returncode,
        stdout=result.stdout,stderr=result.stderr,stdout_file=str(stdout_file),stderr_file=str(stderr_file),
        stdout_bytes=len(stdout_bytes),stderr_bytes=len(stderr_bytes),timed_out=timed_out)
    rows.append(row);(root/'commands-results.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
    assert not timed_out,row
    assert (result.returncode==0)==ok,row
    if ok and (expect_json or pathlib.Path(command[0]).resolve()==pathlib.Path(a.tool).resolve()):
        assert result.stdout.strip(),f'successful command omitted JSON protocol output: {row}'
        for line in result.stdout.splitlines():assert isinstance(json.loads(line),dict),row
    return result

def capture_self_test():
    padding='x'*(128*1024)
    valid=run([sys.executable,'-c',"import json,os; os.write(1,(json.dumps({'capture':True,'padding':'x'*(128*1024)})+'\\n').encode()); os.write(2,b'capture-eof\\n')"],expect_json=True)
    assert json.loads(valid.stdout)==dict(capture=True,padding=padding) and valid.stderr=='capture-eof\n'
    try:run([sys.executable,'-c','pass'],expect_json=True)
    except AssertionError as error:assert 'omitted JSON protocol output' in str(error),error
    else:raise AssertionError('empty-output exit0 must never pass the command protocol')
    try:run([sys.executable,'-c',"print('incomplete JSON')"],expect_json=True)
    except json.JSONDecodeError:pass
    else:raise AssertionError('malformed-output exit0 must never pass the command protocol')
    assert all(not row['timed_out'] and row['exit']==0 and row['pid']>0 for row in rows)
def fixture(name,accepted=False,mode=None):
    folder=root/name;folder.mkdir();run([a.fixtures,folder,mode or ('accepted-unpublished' if accepted=='unpublished' else 'accepted' if accepted else 'fixture')])
    dirs=list(folder.glob('run-*'));assert len(dirs)==1
    d=dirs[0];meta=json.loads((d/'fixture.json').read_text())
    args=[a.tool,'--image',d/'fixture.apfs','--offset','0','--container',meta['container'],'--volume',meta['volume'],'--oid','101','--xid',str(meta['xid']),
        '--quota-blocks','64','--reserve-blocks','20','--wal',f'101={d / "101.wal"}','--wal',f'102={d / "102.wal"}']
    return d,meta,args
def file_id(path):
    info=path.stat();assert info.st_ino,'Windows original file ID must be available'
    return info.st_dev,info.st_ino

def state(d):
    return {x.name:(hashlib.sha256(x.read_bytes()).hexdigest(),file_id(x),x.stat().st_file_attributes)
            for x in d.iterdir() if x.is_file()}
def replace(args,key,value):
    result=list(args);result[result.index(key)+1]=str(value);return result

def replace_wal(args,oid,path):
    result=list(args)
    at=next(i+1 for i,x in enumerate(result[:-1]) if x=='--wal' and str(result[i+1]).startswith(f'{oid}='))
    result[at]=f'{oid}={path}';return result

def unchanged_refusal(args,d,reason=None):
    before=state(d);refused=run(args,False);assert state(d)==before,'refusal changed original image/WAL bytes, IDs or attributes'
    if reason:assert reason in refused.stderr,refused.stderr
    return refused

def verify_native(d,mode):
    before=state(d);run([a.fixtures,d,mode]);assert state(d)==before,'native readback must not change originals'

def finish():
    print(f'PASS private command {len(rows)} process checks; real original WALs, exact identity, token, census, busy owner, clear, actual WAL replay')
    (root/'PASS.json').write_text(json.dumps(dict(passed=True,process_checks=len(rows),
        tool_sha256=hashlib.sha256(pathlib.Path(a.tool).read_bytes()).hexdigest()),indent=2))

def production_cases():
    d,meta,args=fixture('production-command',mode='production');before=state(d)
    plan=json.loads(run(args+['--dry-run']).stdout);assert state(d)==before
    assert plan['operation']==20 and len(plan['volumes'])==2
    unchanged_refusal(args+['--commit','--confirm','0'*64],d,'confirmation does not bind this exact plan')
    published=json.loads(run(args+['--commit','--confirm',plan['confirm']]).stdout.splitlines()[-1]);assert published['durable']
    after=state(d);assert after['fixture.apfs']!=before['fixture.apfs'] and after['102.wal']==before['102.wal']
    verify_native(d,'verify-production')
    unchanged_refusal(args+['--commit','--confirm',plan['confirm']],d)
    clear=replace(replace(replace(args,'--xid',published['checkpointXid']),'--quota-blocks',0),'--reserve-blocks',0)
    clearplan=json.loads(run(clear+['--dry-run']).stdout);assert state(d)==after
    assert json.loads(run(clear+['--commit','--confirm',clearplan['confirm']]).stdout.splitlines()[-1])['durable']
    verify_native(d,'verify-production-clear')

    for mode in ['production-accepted','production-accepted-unpublished']:
        d,meta,args=fixture(mode,mode=mode);before=state(d);recover=args+['--recover']
        unchanged_refusal(args+['--dry-run'],d,'conflicting accepted session or replay')
        plan=json.loads(run(recover+['--dry-run']).stdout);assert state(d)==before
        unchanged_refusal(recover+['--commit','--confirm','0'*64],d,'confirmation does not bind this exact plan')
        publication=json.loads(run(recover+['--commit','--confirm',plan['confirm']]).stdout.splitlines()[-1]);assert publication['durable']
        after=state(d)
        assert (after['fixture.apfs']==before['fixture.apfs'])==(mode=='production-accepted')
        assert after['102.wal']==before['102.wal'],'original peer must remain byte/ID/attribute invariant during replay'
        verify_native(d,'verify-production')
        unchanged_refusal(recover+['--commit','--confirm',plan['confirm']],d)
        unchanged_refusal(replace(recover,'--xid',publication['checkpointXid'])+['--dry-run'],d,'recovery requires one actual accepted intent')

    for mode,reason in [('production-unknown','original WAL identity unproven'),('production-mixed','original WAL mixed identities')]:
        d,meta,args=fixture(mode,mode=mode)
        refused=unchanged_refusal(args+['--dry-run'],d,reason);assert not refused.stdout.strip()
        unchanged_refusal(args+['--recover','--dry-run'],d,reason)

    for oid in [101,102]:
        d,meta,args=fixture(f'missing-{oid}',mode='production')
        plan=json.loads(run(args+['--dry-run']).stdout);wal=d/f'{oid}.wal';wal.unlink()
        unchanged_refusal(args+['--dry-run'],d);assert not wal.exists(),'preview must not recreate original WAL'
        unchanged_refusal(args+['--commit','--confirm',plan['confirm']],d);assert not wal.exists(),'commit must not recreate original WAL'
        absent=d/'missing-parent'/f'{oid}.wal';changed=replace_wal(args,oid,absent)
        unchanged_refusal(changed+['--dry-run'],d,'WAL parent must already exist')
        unchanged_refusal(changed+['--commit','--confirm',plan['confirm']],d,'WAL parent must already exist')
        assert not absent.parent.exists(),'missing parent must remain absent'

    d,meta,args=fixture('wal-alias',mode='production')
    unchanged_refusal(replace_wal(args,102,d/'101.wal')+['--dry-run'],d,'WAL paths must be distinct')
    unchanged_refusal(replace_wal(args,101,d/'fixture.apfs')+['--dry-run'],d,'WAL cannot alias image')
    link=d/'linked.wal';os.link(d/'101.wal',link);assert file_id(link)==file_id(d/'101.wal')
    unchanged_refusal(replace_wal(args,102,link)+['--dry-run'],d,'original single-link WAL required')

    for oid in [101,102]:
        d,meta,args=fixture(f'same-bytes-swap-{oid}',mode='production')
        plan=json.loads(run(args+['--dry-run']).stdout);wal=d/f'{oid}.wal'
        original=wal.read_bytes();identity=file_id(wal)
        wal.rename(d/f'{oid}.original.wal');wal.write_bytes(original)
        assert wal.read_bytes()==original and file_id(wal)!=identity,'swap changes only original file identity'
        before=state(d);newplan=json.loads(run(args+['--dry-run']).stdout);assert state(d)==before
        assert newplan['confirm']!=plan['confirm'],'confirmation must bind original WAL file ID even with identical bytes'
        unchanged_refusal(args+['--commit','--confirm',plan['confirm']],d,'confirmation does not bind this exact plan')

    d,meta,args=fixture('production-crc',mode='production');wal=d/'102.wal'
    raw=bytearray(wal.read_bytes());raw[len(raw)//2]^=1;wal.write_bytes(raw)
    refused=unchanged_refusal(args+['--dry-run'],d,'original WAL strict inspection failed');assert not refused.stdout.strip()

    for oid in [101,102]:
        d,meta,args=fixture(f'wal-readonly-{oid}',mode='production')
        plan=json.loads(run(args+['--dry-run']).stdout);wal=d/f'{oid}.wal';wal.chmod(stat.S_IREAD)
        try:unchanged_refusal(args+['--commit','--confirm',plan['confirm']],d)
        finally:wal.chmod(stat.S_IWRITE|stat.S_IREAD)

    for identity in ['canonical','production']:
        for oid in [101,102]:
            d,meta,args=fixture(f'busy-{identity}-{oid}',mode='production')
            plan=json.loads(run(args+['--dry-run']).stdout)
            command=[str(a.fixtures),str(d),f'hold-{identity}-{oid}']
            witness=subprocess.Popen(command,cwd=root,env=env,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,encoding='utf-8')
            try:
                deadline=time.monotonic()+10
                while not (d/'wal-hold.ready').exists() and witness.poll() is None and time.monotonic()<deadline:time.sleep(.01)
                assert (d/'wal-hold.ready').exists() and witness.poll() is None,'native named-pipe witness must own the exact legal identity'
                unchanged_refusal(args+['--dry-run'],d,'VolumeQuotaWalBusy')
                unchanged_refusal(args+['--commit','--confirm',plan['confirm']],d,'VolumeQuotaWalBusy')
            finally:
                (d/'wal-hold.stop').write_text('stop',encoding='ascii')
                try:out,err=witness.communicate(timeout=10)
                except subprocess.TimeoutExpired:
                    witness.kill();out,err=witness.communicate();raise AssertionError('native owned WAL witness did not stop')
                rows.append(dict(command=command,exit=witness.returncode,stdout=out,stderr=err))
                (root/'commands-results.json').write_text(json.dumps(rows,indent=2),encoding='utf-8')
                assert witness.returncode==0,(out,err)

if a.capture_self_test:
    capture_self_test();print('PASS output capture: complete JSON, empty-output refusal, malformed-output refusal; 3 owned processes')
    (root/'PASS.json').write_text(json.dumps(dict(passed=True,capture_only=True,process_checks=len(rows)),indent=2))
    raise SystemExit(0)

if a.production_only:
    production_cases();finish();raise SystemExit(0)

d,meta,args=fixture('command')
before=state(d);dry=run(args+['--dry-run']);plan=json.loads(dry.stdout)
assert state(d)==before,'dry-run must not write image or journals'
assert plan['operation']==20 and len(plan['volumes'])==2
for altered in [replace(args,'--volume','b'*32),replace(args,'--container','b'*32),replace(args,'--oid',102),replace(args,'--xid',meta['xid']+1),
                replace(args,'--offset',4096),replace(args,'--quota-blocks',1),replace(args,'--reserve-blocks',513),args[:-2]]:
    run(altered+['--dry-run'],False);assert state(d)==before
run(args+['--commit','--confirm','0'*64],False);assert state(d)==before
run(replace(args,'--quota-blocks',128)+['--commit','--confirm',plan['confirm']],False);assert state(d)==before
run(replace(args,'--reserve-blocks',21)+['--commit','--confirm',plan['confirm']],False);assert state(d)==before
run(args+['--dry-run','--commit','--confirm',plan['confirm']],False);assert state(d)==before
original_peer=(d/'102.wal').read_bytes();(d/'102.wal').write_bytes(b'malformed intent')
malformed=state(d);run(args+['--dry-run'],False);assert state(d)==malformed
(d/'102.wal').write_bytes(original_peer);assert state(d)==before
kernel=ctypes.WinDLL('kernel32',use_last_error=True)
kernel.CreateFileW.argtypes=[ctypes.c_wchar_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
kernel.CreateFileW.restype=ctypes.c_void_p;kernel.CloseHandle.argtypes=[ctypes.c_void_p]
h=kernel.CreateFileW(str(d/'fixture.apfs'),0x80000000,7,None,3,0,None)
assert h not in (None,ctypes.c_void_p(-1).value)
try:run(args+['--commit','--confirm',plan['confirm']],False);assert state(d)==before
finally:kernel.CloseHandle(h)
done=run(args+['--commit','--confirm',plan['confirm']]);published=json.loads(done.stdout.splitlines()[-1]);assert published['durable']
after=state(d);assert after['fixture.apfs']!=before['fixture.apfs']
verify_native(d,'verify-production')
run(args+['--commit','--confirm',plan['confirm']],False);assert state(d)==after
clear=replace(replace(replace(args,'--xid',published['checkpointXid']),'--quota-blocks',0),'--reserve-blocks',0)
clearplan=json.loads(run(clear+['--dry-run']).stdout);assert state(d)==after
cleared=run(clear+['--commit','--confirm',clearplan['confirm']]);assert json.loads(cleared.stdout.splitlines()[-1])['durable']
verify_native(d,'verify-production-clear')

# Recovery command uses the actual accepted WAL written by the engine fixture,
# on that same image file identity (no copied/fictional journal).
d,meta,args=fixture('recovery',True);before=state(d)
recover=args+['--recover'];plan=json.loads(run(recover+['--dry-run']).stdout);assert state(d)==before
run(recover+['--commit','--confirm','0'*64],False);assert state(d)==before
replayed=run(recover+['--commit','--confirm',plan['confirm']]);assert json.loads(replayed.stdout.splitlines()[-1])['durable']
after=state(d);assert after['fixture.apfs']==before['fixture.apfs'],'published replay must only finalize WAL'
verify_native(d,'verify-canonical')
run(recover+['--commit','--confirm',plan['confirm']],False);assert state(d)==after
# Accepted but unpublished recovery previews both source proof and capacity.
d,meta,args=fixture('unpublished-recovery','unpublished');before=state(d)
recover=args+['--recover'];plan=json.loads(run(recover+['--dry-run']).stdout);assert state(d)==before
result=run(recover+['--commit','--confirm',plan['confirm']]);assert json.loads(result.stdout.splitlines()[-1])['durable']
after=state(d);assert after['fixture.apfs']!=before['fixture.apfs']
verify_native(d,'verify-canonical')
run(recover+['--commit','--confirm',plan['confirm']],False);assert state(d)==after

# A valid WAL envelope is insufficient for recovery preview. Use the actual
# retained publication with a checksum-valid but false allocated count.
folder=root/'corrupt-recovery';folder.mkdir();run([a.fixtures,folder,'review-published'])
d=next(folder.glob('run-*'));image=d/'review-published.apfs';wal=d/'review-published.wal'
meta=json.loads((d/'fixture.json').read_text())
invalid=[a.tool,'--image',image,'--offset','0','--container',meta['container'],'--volume',meta['volume'],
    '--oid','101','--xid',str(meta['xid']),'--quota-blocks','64','--reserve-blocks','20','--wal',f'101={wal}',
    '--wal',f'102={d / "peer.wal"}','--recover','--dry-run']
before=state(d);refused=run(invalid,False);assert state(d)==before and not refused.stdout.strip()
assert 'VolumeQuotaReserveExactChargedAllocationUnproven' in refused.stderr,refused.stderr

# Exact unsigned parsing and block-to-byte conversion must refuse overflow.
d,meta,args=fixture('bounds');before=state(d)
for key,value in [('--quota-blocks',2**64-1),('--quota-blocks',2**64//4096),('--reserve-blocks',2**64-1),
                  ('--quota-blocks',2**64),('--offset',2**64-1),('--quota-blocks','-1')]:
    run(replace(args,key,value)+['--dry-run'],False);assert state(d)==before

d,meta,args=fixture('canonical-history',mode='canonical');before=state(d)
plan=json.loads(run(args+['--dry-run']).stdout);assert state(d)==before
assert json.loads(run(args+['--commit','--confirm',plan['confirm']]).stdout.splitlines()[-1])['durable']
assert state(d)['102.wal']==before['102.wal'];verify_native(d,'verify-canonical-history')

production_cases();finish()
