"""Focused transport/output regressions; only synthetic regular image files."""
import argparse, ctypes as C, json, os, subprocess, sys, time, msvcrt
from pathlib import Path
from ctypes import wintypes as W
pa=argparse.ArgumentParser(); pa.add_argument('--root',required=True); pa.add_argument('--tool',required=True); pa.add_argument('--label',required=True); pa.add_argument('--vectors'); pa.add_argument('--observer')
a=pa.parse_args(); root=Path(a.root); tool=Path(a.tool)
# Reuse 544's public fixture selectors and production subprocess helpers.
sys.argv=[__file__,'--root',str(root),'--tool',str(tool)]
if a.vectors: sys.argv += ['--vectors',a.vectors]
ns={'__file__':str(Path(__file__).with_name('EncryptedReadToolIntegration.py')), '__name__':'review_helpers'}
exec(compile(Path(ns['__file__']).read_text(),ns['__file__'],'exec'),ns)
k=ns['k']; results=[]
def check(ok,msg):
    if not ok: raise AssertionError(msg)
def case(name,fn):
    t=time.monotonic()
    try: fn(); result={'name':name,'pass':True}
    except Exception as e: result={'name':name,'pass':False,'detail':str(e)}
    result['seconds']=round(time.monotonic()-t,3); results.append(result); print(json.dumps(result),flush=True)
def source_cmd():
    image=root/'fixtures/encrypted.img'
    return [str(tool),'--mode','source','--image',str(image),'--store-offset','0','--store-size',str(image.stat().st_size),'--operation-timeout-ms','200']
def source_output(block):
    rd,wr=os.pipe()
    if block: os.write(wr,b'X'*4096)
    else: os.close(rd); rd=None
    p=None
    try:
        p=subprocess.Popen(source_cmd(),stdin=subprocess.DEVNULL,stdout=wr,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
        os.close(wr); wr=None
        try: p.wait(timeout=2)
        except subprocess.TimeoutExpired: raise AssertionError('output exceeded operation deadline')
        check(p.returncode == (6 if block else 8),'expected output/cancellation failure, observed '+str(p.returncode))
    finally:
        if p and p.poll() is None: p.kill(); p.wait()
        if p: p.stderr.close()
        if rd is not None: os.close(rd)
        if wr is not None: os.close(wr)
    check(ns['writer_available'](root/'fixtures/encrypted.img'),'lease released')
def cancel_type(kind):
    f=None; event=None
    if kind=='file':
        f=open(root/'fixtures/encrypted.img','rb'); handle=msvcrt.get_osfhandle(f.fileno())
    else:
        event=k.CreateEventW(None,False,False,None); handle=event
    k.SetHandleInformation(handle,1,1)
    si=subprocess.STARTUPINFO(); si.lpAttributeList={'handle_list':[handle]}
    try:
        p=subprocess.run(ns['command']()+['--cancel-handle',str(handle)],input=ns['frame'](),capture_output=True,startupinfo=si,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=3)
        check(p.returncode==2 and b'InvalidCancellationHandle' in p.stderr,'non-manual-event accepted: '+str(p.returncode))
        check(not p.stdout,'unexpected output')
    finally:
        if f: f.close()
        if event: k.CloseHandle(event)
def blocked_binary():
    p=subprocess.Popen(ns['command'](mode='read',overrides={'--operation-timeout-ms':'300'}),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        p.stdin.write(ns['frame']()); p.stdin.close(); p.stdin=None
        p.wait(timeout=2)
        out,err=p.communicate(timeout=2)
        check(p.returncode==6,'blocked binary exit '+str(p.returncode))
        check(len(out)<16247,'cancelled output must be incomplete')
        check(ns['writer_available'](root/'fixtures/encrypted.img'),'lease released')
    finally:
        if p.poll() is None: p.kill(); p.wait()
def broken_binary():
    rd,wr=os.pipe(); os.close(rd)
    try:
        p=subprocess.run(ns['command'](mode='read'),input=ns['frame'](),stdout=wr,stderr=subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW,timeout=3)
        check(p.returncode==8 and b'OutputFailure' in p.stderr,'broken binary output must fail')
    finally: os.close(wr)
    check(ns['writer_available'](root/'fixtures/encrypted.img'),'lease released')
def blocked_stderr():
    rd,wr=os.pipe(); os.write(wr,b'X'*4096)
    p=None
    try:
        p=subprocess.Popen(ns['command'](overrides={'--operation-timeout-ms':'200'}),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=wr,creationflags=subprocess.CREATE_NO_WINDOW)
        os.close(wr); wr=None
        p.stdin.write(ns['frame']()); p.stdin.close(); p.stdin=None
        p.wait(timeout=2)
        check(p.returncode==6,'blocked stderr must cancel')
        check(not p.stdout.read(),'no result published')
    finally:
        if p and p.poll() is None: p.kill(); p.wait()
        if p: p.stdout.close()
        os.close(rd)
        if wr is not None: os.close(wr)
    check(ns['writer_available'](root/'fixtures/encrypted.img'),'lease released')
def substituted_source():
    image=root/'fixtures/substitution.img'; image.write_bytes((root/'fixtures/encrypted.img').read_bytes())
    cmd=ns['command'](image=image)
    replacement=root/'fixtures/substitution-new.img'; replacement.write_bytes(image.read_bytes())
    os.replace(replacement,image)
    p=subprocess.run(cmd,input=ns['frame'](),capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=3)
    check(p.returncode==3 and b'SourceIdentityMismatch' in p.stderr,'same-content replacement must refuse exact source token')
    check(not p.stdout and b'Unlocking' not in p.stderr,'substitution fails before unlock')
def ancestor_reparse():
    link=root/'fixtures/ancestor-link'
    target=root/'fixtures/ancestor-target'; target.mkdir(exist_ok=True)
    (target/'encrypted.img').write_bytes((root/'fixtures/encrypted.img').read_bytes())
    if link.is_symlink(): link.unlink()
    os.symlink(target,link,target_is_directory=True)
    cmd=source_cmd(); cmd[cmd.index('--image')+1]=str(link/'encrypted.img')
    p=subprocess.run(cmd,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=3)
    check(p.returncode==3 and not p.stdout,'ancestor reparse must be refused')
    check(ns['writer_available'](root/'fixtures/encrypted.img'),'reparse rejection releases handles')
def observer_lease(writer):
    exe=Path(a.observer) if a.observer else root/'build/ApfsVerifierObserverTests.exe'
    cmd=[str(exe),str(root/'fixtures/encrypted.img' if writer else root/'fixtures/review-observer.img')]
    if writer: cmd.append('--writer-admission')
    p=subprocess.run(cmd,capture_output=True,creationflags=subprocess.CREATE_NO_WINDOW,timeout=3)
    check(p.returncode==(2 if writer else 0),'observer exit contract: '+str(p.returncode))
    check((b'cannot acquire read-only verification image lease' in p.stderr) if writer else (b'8 checks' in p.stdout),'observer evidence')
case('observer_lease_eight_checks',lambda:observer_lease(False))
case('observer_writer_public_failure',lambda:observer_lease(True))
case('ancestor_reparse_refused',ancestor_reparse)
case('binary_broken_stdout',broken_binary)
case('blocked_stderr_deadline',blocked_stderr)
case('same_content_source_substitution',substituted_source)
case('source_broken_stdout',lambda:source_output(False))
case('source_blocked_stdout_deadline',lambda:source_output(True))
case('cancel_file_refused',lambda:cancel_type('file'))
case('cancel_auto_reset_event_refused',lambda:cancel_type('auto'))
case('binary_blocked_stdout_deadline',blocked_binary)
(root/'evidence'/('review-'+a.label+'.json')).write_text(json.dumps({'cases':results,'passed':sum(x['pass'] for x in results),'failed':sum(not x['pass'] for x in results)},indent=2))
sys.exit(any(not x['pass'] for x in results))
