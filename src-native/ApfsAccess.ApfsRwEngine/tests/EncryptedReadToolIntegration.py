"""One focused Windows batch. Only original, deterministic public fixture material.
Actual subprocess-created parent pipes; no credentials in process args or files.
Run with --root <private candidate directory>. All evidence is public metadata.
"""
import argparse, ctypes as C, hashlib, json, os, re, struct, subprocess, time, msvcrt, sys
from pathlib import Path
from ctypes import wintypes as W
from EncryptedFailureEvidence import capture_failure, finish_cleanup, persist_failures

parser = argparse.ArgumentParser()
parser.add_argument('--root', required=True)
parser.add_argument('--tool')
parser.add_argument('--fixture-builder')
parser.add_argument('--vectors')
args = parser.parse_args()
ROOT = Path(args.root).resolve()
os.environ['TEMP'] = os.environ['TMP'] = str(ROOT / 'temp')
EXE = Path(args.tool) if args.tool else ROOT / 'build/ApfsEncryptedReadTool.exe'
BUILDER = Path(args.fixture_builder) if args.fixture_builder else ROOT / 'build/EncryptedReadToolFixtures.exe'
VECTORS = Path(args.vectors) if args.vectors else ROOT/'baseline/tests/ApfsKeybagUnlockVectors.h'
FIXTURES = ROOT / 'fixtures'
EVIDENCE = ROOT / 'evidence'
for directory in [FIXTURES,EVIDENCE,ROOT/'temp']: directory.mkdir(parents=True,exist_ok=True)
k = C.WinDLL('kernel32', use_last_error=True)
k.CreateFileW.argtypes = [W.LPCWSTR,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,W.DWORD,W.HANDLE]
k.CreateFileW.restype = W.HANDLE
k.CloseHandle.argtypes = [W.HANDLE]
k.MoveFileExW.argtypes = [W.LPCWSTR,W.LPCWSTR,W.DWORD]
k.CreateEventW.argtypes = [C.c_void_p,W.BOOL,W.BOOL,W.LPCWSTR]
k.CreateEventW.restype = W.HANDLE
k.SetEvent.argtypes = [W.HANDLE]
k.SetHandleInformation.argtypes = [W.HANDLE,W.DWORD,W.DWORD]
k.OpenProcess.argtypes = [W.DWORD,W.BOOL,W.DWORD]
k.OpenProcess.restype = W.HANDLE
INVALID = C.c_void_p(-1).value
records = []
failure_evidence = []

def vector(name):
    text = VECTORS.read_text(encoding='utf-8-sig')
    value = re.search(r'\b'+name+r'\s*=\s*"([0-9a-f]+)"', text).group(1)
    return bytes.fromhex(value)

# Synthetic public test vectors only. Never put these bytes into diagnostics.
SECRET = vector('Password')
def frame(payload=SECRET): return b'APC1'+struct.pack('<I',len(payload))+payload
def check(condition, label):
    if not condition: raise AssertionError(label)
def source(image):
    command=[str(EXE),'--mode','source','--image',str(image),'--store-offset','0','--store-size',str(image.stat().st_size)]
    p=subprocess.run(command,capture_output=True,timeout=5)
    check(p.returncode == 0,'source probe')
    return json.loads(p.stdout)['sourceId']
def command(image=None, mode='inspect', overrides=None):
    image=image or FIXTURES/'encrypted.img'
    selectors={
        '--mode':mode,'--image':str(image),'--store-offset':'0','--store-size':str(image.stat().st_size),
        '--source-id':source(image),'--container-uuid':vector('ContainerUuid').hex(),
        '--volume-uuid':vector('VolumeUuid').hex(),'--user-uuid':vector('UserUuid').hex(),
        '--volume-oid':'101','--checkpoint-xid':'7','--container-bag-oid':'901','--container-bag-xid':'7',
        '--volume-bag-oid':'902','--volume-bag-xid':'7','--bag-length':'includes-header',
        '--credential-timeout-ms':'800','--operation-timeout-ms':'5000'}
    if mode=='read': selectors.update({'--inode':'1000','--offset':'0','--length':'16247'})
    selectors.update(overrides or {})
    result=[str(EXE)]
    for key,value in selectors.items():
        if value is not None: result += [key,value]
    if mode=='read': result.append('--binary-stdout')
    return result

def process_commandline(pid):
    class US(C.Structure):
        _fields_=[('Length',W.USHORT),('MaximumLength',W.USHORT),('Buffer',C.c_void_p)]
    n=C.WinDLL('ntdll')
    n.NtQueryInformationProcess.argtypes=[W.HANDLE,W.ULONG,C.c_void_p,W.ULONG,C.POINTER(W.ULONG)]
    n.NtQueryInformationProcess.restype=C.c_long
    handle=k.OpenProcess(0x410,False,pid)
    check(bool(handle),'open exact child for argument audit')
    try:
        count=W.ULONG()
        n.NtQueryInformationProcess(handle,60,None,0,C.byref(count))
        check(0 < count.value < 65536,'bounded child commandline size')
        buf=C.create_string_buffer(count.value)
        check(n.NtQueryInformationProcess(handle,60,buf,count,C.byref(count))>=0,'capture actual child commandline')
        value=US.from_buffer(buf)
        return C.wstring_at(value.Buffer,value.Length//2)
    finally: k.CloseHandle(handle)

def writer_available(image):
    h=k.CreateFileW(str(image),0x40000000,7,None,3,0,None)
    if h != INVALID: k.CloseHandle(h); return True
    return False

def run(name, cmd=None, payload=frame(), expected_exit=0, expected_error=None,
        expected_bytes=None, hold=False, lease_check=False, cancel=False, input_kind='pipe', audit=False):
    cmd=cmd or command()
    startup=None; event=None; opened=None; unprotected_writer=None
    if cancel:
        event=k.CreateEventW(None,True,False,None)
        check(bool(event) and k.SetHandleInformation(event,1,1),'create inherited cancellation event')
        startup=subprocess.STARTUPINFO()
        startup.lpAttributeList={'handle_list':[event]}
        cmd += ['--cancel-handle',str(event)]
    if input_kind=='unprotected':
        adv=C.WinDLL('advapi32')
        adv.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes=[W.LPCWSTR,W.DWORD,C.c_void_p,C.c_void_p]
        sd=C.c_void_p()
        check(adv.ConvertStringSecurityDescriptorToSecurityDescriptorW('D:P(A;;GA;;;WD)',1,C.byref(sd),None),'public permissive pipe setup')
        try:
            class SA(C.Structure):
                _fields_=[('nLength',W.DWORD),('lpSecurityDescriptor',C.c_void_p),('bInheritHandle',W.BOOL)]
            sa=SA(C.sizeof(SA),sd,True); read_handle=W.HANDLE(); write_handle=W.HANDLE()
            k.CreatePipe.argtypes=[C.POINTER(W.HANDLE),C.POINTER(W.HANDLE),C.POINTER(SA),W.DWORD]
            check(k.CreatePipe(C.byref(read_handle),C.byref(write_handle),C.byref(sa),0),'create public permissive pipe')
            reader=msvcrt.open_osfhandle(read_handle.value,os.O_RDONLY|os.O_BINARY)
            unprotected_writer=msvcrt.open_osfhandle(write_handle.value,os.O_WRONLY|os.O_BINARY)
            opened=os.fdopen(reader,'rb',buffering=0); stdin=opened
        finally:
            C.WinDLL('kernel32').LocalFree.argtypes=[C.c_void_p]
            C.WinDLL('kernel32').LocalFree(sd)
    elif input_kind=='disk':
        opened=open(FIXTURES/'encrypted.img','rb'); stdin=opened
    elif input_kind=='char': stdin=subprocess.DEVNULL
    else: stdin=subprocess.PIPE
    start=time.monotonic()
    p=subprocess.Popen(cmd,stdin=stdin,stdout=subprocess.PIPE,stderr=subprocess.PIPE,
        startupinfo=startup,close_fds=True,creationflags=subprocess.CREATE_NO_WINDOW)
    prefix=b''; actual_args=None; locked=False; timeout_evidence=None
    try:
        if hold or lease_check or cancel or audit:
            # Child emits this only after its real deny-write/delete lease exists.
            prefix=p.stderr.readline()
            check(b'AwaitingCredential' in prefix,name+': lease-ready state')
        if audit: actual_args=process_commandline(p.pid)
        if lease_check:
            image=Path(cmd[cmd.index('--image')+1])
            check(not writer_available(image),name+': writer denied during credential wait')
            check(not k.MoveFileExW(str(image),str(image)+'.moved',0),name+': rename denied')
            replacement=FIXTURES/'replacement.img'
            replacement.write_bytes(b'public replacement probe')
            check(not k.MoveFileExW(str(replacement),str(image),1),name+': replacement denied')
            locked=True
        if cancel: k.SetEvent(event)
        if input_kind=='pipe':
            try:
                if payload: p.stdin.write(payload); p.stdin.flush()
            except BrokenPipeError: pass
            if not hold:
                p.stdin.close(); p.stdin=None
        if hold:
            p.wait(timeout=7)
            p.stdin.close(); p.stdin=None
        try:
            out,err=p.communicate(timeout=7)
        except subprocess.TimeoutExpired as error:
            if name == 'permissive_pipe_refused':
                timeout_evidence = capture_failure(name,p,start,error,prefix=prefix,
                                                   credential=SECRET,timeout=7)
                failure_evidence.append(timeout_evidence)
                persist_failures(EVIDENCE/'failure-evidence.json',failure_evidence)
            raise
        err=prefix+err
        check(p.returncode==expected_exit,name+': exact exit (observed '+str(p.returncode)+')')
        if expected_error: check(expected_error.encode() in err,name+': typed error')
        if expected_bytes is not None: check(out==expected_bytes,name+': exact file bytes')
        if expected_exit: check(not out,name+': no successful output on failure')
        if expected_exit==0 and '--binary-stdout' not in cmd:
            metadata=json.loads(out)
            check(metadata['mode']=='inode-metadata' and metadata['files']==[
                {'inode':'1000','size':'16247','defaultCryptoId':'2457'}],name+': exact metadata')
        for blob in [out,err,' '.join(cmd).encode(),(actual_args or '').encode()]:
            check(SECRET not in blob and SECRET.hex().encode() not in blob,name+': no credential leakage')
        image=Path(cmd[cmd.index('--image')+1]) if '--image' in cmd else FIXTURES/'encrypted.img'
        check(writer_available(image),name+': image lease released on child exit')
        record={'name':name,'exit':p.returncode,'seconds':round(time.monotonic()-start,3),
            'pid':p.pid,'exactChildExited':p.poll() is not None,'stdoutBytes':len(out),
            'stdoutSha256':hashlib.sha256(out).hexdigest(),'stderr':err.decode('ascii'),
            'args':cmd,'capturedCommandLine':actual_args,'leaseExclusionChecked':locked,'pass':True}
        records.append(record)
        print('PASS '+name,flush=True)
    finally:
        kill_requested=False; cleanup_error=None
        try:
            if p.poll() is None:
                kill_requested=True
                p.kill(); p.wait(timeout=5)
        except BaseException as error:
            cleanup_error=error
            raise
        finally:
            try:
                if opened: opened.close()
                if unprotected_writer is not None: os.close(unprotected_writer)
                if event: k.CloseHandle(event)
            except BaseException as error:
                cleanup_error=error
                raise
            finally:
                if timeout_evidence is not None:
                    finish_cleanup(timeout_evidence,p,start,kill_requested,cleanup_error,credential=SECRET)
                    persist_failures(EVIDENCE/'failure-evidence.json',failure_evidence)

def batch():
    subprocess.run([str(BUILDER),str(FIXTURES)],check=True,capture_output=True,timeout=5)
    expected=(FIXTURES/'expected.bin').read_bytes()
    run('metadata_production_unlock',audit=True,lease_check=True)
    for label,offset,size in [('full',0,len(expected)),('partial',17,711),('cross_sector',500,1100),
            ('cross_extent',4091,1029),('sparse',8225,777),('eof_tail',len(expected)-99,99),('eof_zero',len(expected),0)]:
        run('read_'+label,command(mode='read',overrides={'--offset':str(offset),'--length':str(size)}),
            expected_bytes=expected[offset:offset+size])
    run('past_eof',command(mode='read',overrides={'--offset':str(len(expected)-1),'--length':'2'}),
        expected_exit=7,expected_error='InvalidArgument')
    run('wrong_password',payload=frame(b'public-incorrect-vector'),expected_exit=5,expected_error='CredentialOrKeyMismatch')
    run('bad_magic',payload=b'NOPE'+frame()[4:],expected_exit=4,expected_error='InvalidFrame')
    run('truncated_header',payload=frame()[:5],expected_exit=4,expected_error='TruncatedFrame')
    run('truncated_payload',payload=frame()[:-2],expected_exit=4,expected_error='TruncatedFrame')
    run('oversized_length',payload=b'APC1'+struct.pack('<I',1025),expected_exit=4,expected_error='OversizedFrame')
    run('empty_length',payload=b'APC1'+struct.pack('<I',0),expected_exit=4,expected_error='InvalidFrame')
    run('extra_byte',payload=frame()+b'X',expected_exit=4,expected_error='InvalidFrame')
    run('nul_byte',payload=frame(b'public\x00vector'),expected_exit=4,expected_error='InvalidFrame')
    run('maximum_bounded_payload',payload=frame(b'x'*1024),expected_exit=5,expected_error='CredentialOrKeyMismatch')
    for label,data in [('header',b'AP'),('payload',frame()[:10]),('eof',frame())]:
        run('never_completed_'+label,command(overrides={'--credential-timeout-ms':'200'}),payload=data,hold=True,
            expected_exit=4,expected_error='Timeout')
    run('orderly_cancel_partial_frame',payload=frame()[:10],hold=True,cancel=True,expected_exit=6,expected_error='Cancelled')
    run('operation_deadline',command(overrides={'--operation-timeout-ms':'200'}),payload=frame()[:10],hold=True,
        expected_exit=6,expected_error='Cancelled')
    run('file_stdin_refused',input_kind='disk',expected_exit=4,expected_error='PipeRequired')
    run('character_stdin_refused',input_kind='char',expected_exit=4,expected_error='PipeRequired')
    run('permissive_pipe_refused',input_kind='unprotected',payload=None,expected_exit=4,expected_error='UnprotectedPipe')
    run('password_option_refused',command()+['--password'],expected_exit=2,expected_error='PasswordArgumentForbidden')
    run('password_equals_refused',command()+['--password='],expected_exit=2,expected_error='PasswordArgumentForbidden')
    for key,value in [('--source-id','windows-file:wrong'),('--container-uuid','0'*32),('--volume-uuid','0'*32),
            ('--user-uuid','0'*32),('--checkpoint-xid','8'),('--volume-oid','102'),('--container-bag-oid','903'),
            ('--container-bag-xid','8'),('--volume-bag-oid','903'),('--volume-bag-xid','8')]:
        run('wrong_'+key[2:],command(overrides={key:value}),expected_exit=3 if key=='--source-id' else 5)
    run('missing_bag_expectation',command(overrides={'--volume-bag-xid':None}),expected_exit=2,expected_error='MissingExactSelector')
    run('unsupported_crypto_profile',command(image=FIXTURES/'unsupported.img'),expected_exit=5,expected_error='UnsupportedFormat')
    run('unknown_bag_profile',command(overrides={'--bag-length':'guess'}),expected_exit=2,expected_error='UnsupportedBagLengthProfile')
    run('wrong_length_convention',command(overrides={'--bag-length':'entries-only'}),expected_exit=5)
    run('wrong_inode',command(mode='read',overrides={'--inode':'1001'}),expected_exit=7,expected_error='FileNotFound')
    run('missing_binary_opt_in',[x for x in command(mode='read') if x!='--binary-stdout'],expected_exit=2,
        expected_error='ExplicitBinaryOutputRequired')
    # An already-open writer must prevent lease admission before credential reads.
    cmd=command(); image=FIXTURES/'encrypted.img'
    h=k.CreateFileW(str(image),0x40000000,7,None,3,0,None)
    check(h!=INVALID,'open prior writer')
    try:
        p=subprocess.run(cmd,input=b'',capture_output=True,timeout=5)
        check(p.returncode==3 and b'ImageLeaseOrScopeFailure' in p.stderr,'existing writer blocks lease')
        records.append({'name':'existing_writer_blocks_lease','exit':p.returncode,'pass':True,'exactChildExited':True})
    finally: k.CloseHandle(h)
    check(writer_available(image),'prior writer released')
    run('retry_after_failures')
    # Exact nonzero container scope, independently supplied rather than discovered.
    image=FIXTURES/'scoped.img'
    probe=subprocess.run([str(EXE),'--mode','source','--image',str(image),'--store-offset','4096',
        '--store-size','524288'],capture_output=True,timeout=5)
    check(probe.returncode==0,'nonzero source scope probe')
    run('exact_nonzero_scope',command(image=image,mode='read',overrides={'--store-offset':'4096',
        '--store-size':'524288','--source-id':json.loads(probe.stdout)['sourceId']}),expected_bytes=expected)
    # Relay inherits grandparent's pipe; receiver must reject the creator/parent mismatch.
    relay=Path(__file__).with_name('EncryptedReadToolRelay.py')
    cmd=[sys.executable,str(relay)]+command()
    p=subprocess.run(cmd,input=b'',capture_output=True,timeout=5)
    check(p.returncode==4 and b'ParentPipeRequired' in p.stderr,'foreign creator pipe refused')
    records.append({'name':'foreign_parent_pipe_refused','exit':p.returncode,'pass':True,'exactChildExited':True})

if __name__ == '__main__':
    try:
        batch()
    except Exception as error:
        # Assertion labels are fixed/public. Never serialize exception objects from I/O.
        records.append({'name':'batch_failure','pass':False,'type':type(error).__name__})
        raise
    finally:
        EVIDENCE.mkdir(exist_ok=True)
        (EVIDENCE/'integration-results.json').write_text(json.dumps({'timezone':'Asia/Shanghai',
            'at':time.strftime('%Y-%m-%dT%H:%M:%S%z'),'cases':records,'failureEvidence':failure_evidence,
            'passed':sum(r['pass'] for r in records),'failed':sum(not r['pass'] for r in records)},indent=2),encoding='utf-8')
