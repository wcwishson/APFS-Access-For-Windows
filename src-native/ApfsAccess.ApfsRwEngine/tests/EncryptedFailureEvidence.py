"""Failure-only public metadata. Never persist child stdout or unknown diagnostics."""
import base64
import hashlib
import json
from pathlib import Path
import time


TEXT_LIMIT = 2048
INPUT_LIMIT = 8192
ERRORS = frozenset('''None InvalidArgument UnlockFailed UnsupportedEncryptionLayout
SourceIdentityMismatch ResourceLimit ReadFailure CryptoFailure MetadataIntegrityFailure
Closed Cancelled FileNotFound NotDirectory XattrNotFound NamespaceUnavailable
UnsupportedFormat Malformed IdentityMismatch IntegrityFailure CredentialOrKeyMismatch
RateLimited UnlockFailure PipeRequired UnprotectedPipe ParentPipeRequired InvalidFrame
TruncatedFrame OversizedFrame Timeout PasswordArgumentForbidden ImageLeaseOrScopeFailure
InvalidPublicNumber InvalidPublicSelector InvalidUuid CancellationSetupFailure OutputFailure
InvalidCancellationHandle DuplicateOption InvalidPublicOptions MissingExactSelector
UnsupportedBagLengthProfile ExplicitBinaryOutputRequired'''.split())
PUBLIC_VALUES = {
    'state': frozenset(('Locked', 'Unlocking')),
    'phase': frozenset(('AwaitingCredential', 'Closed')),
    'output': frozenset(('inode-metadata', 'binary-file-data')),
    'error': ERRORS, 'readError': ERRORS, 'unlockError': ERRORS,
}


def malformed_line_metadata(data, forms, input_truncated):
    lines = data.splitlines()
    credential_seen = any(form in data for form in forms if form)
    metadata = []
    for index, line in enumerate(lines[:64], 1):
        try:
            json.loads(line)
        except (ValueError, UnicodeDecodeError, RecursionError):
            pass
        else:
            continue
        if not line:
            category = 'empty'
        elif not line.strip(b' \t\r\n\v\f'):
            category = 'ascii-whitespace-only'
        else:
            try:
                line.decode('utf-8', 'strict')
            except UnicodeDecodeError:
                category = 'non-utf8'
            else:
                category = 'non-json-text'
        truncated = input_truncated and index == len(lines) and not data.endswith((b'\r', b'\n'))
        item = {'line': index, 'byteLength': len(line), 'category': category,
                'truncated': truncated}
        # Count only complete whitespace lines, without credential-derived bytes.
        if category in ('empty', 'ascii-whitespace-only') and not credential_seen and not truncated:
            item['whitespaceCounts'] = {name: line.count(byte) for name, byte in (
                ('space', b' '), ('tab', b'\t'), ('cr', b'\r'), ('lf', b'\n'),
                ('verticalTab', b'\v'), ('formFeed', b'\f'))}
        metadata.append(item)
    return metadata, input_truncated or len(lines) > 64


def diagnostic_text(data, credential=None):
    # Parse only a bounded prefix; unknown keys, values and malformed lines are opaque.
    bounded = data[:INPUT_LIMIT]
    forms = set()
    if credential:
        forms = {credential, credential.hex().encode(), credential.hex().upper().encode(),
                 base64.b64encode(credential)}
        try:
            text = credential.decode('utf-8')
            forms.add(json.dumps(text)[1:-1].encode())
            forms.add(json.dumps(text, ensure_ascii=False)[1:-1].encode())
        except UnicodeDecodeError:
            pass
    # Classify original bytes before substitutions change their lengths or lines.
    malformed, metadata_truncated = malformed_line_metadata(bounded, forms, len(data) > INPUT_LIMIT)
    if credential:
        for form in sorted(forms, key=len, reverse=True):
            bounded = bounded.replace(form, b'[redacted]')
    rendered = []
    kinds = []
    for line in bounded.splitlines():
        try:
            value = json.loads(line)
        except (ValueError, UnicodeDecodeError, RecursionError):
            rendered.append('[redacted malformed diagnostic]')
            kinds.append('malformed-json')
            continue
        if not isinstance(value, dict):
            rendered.append('[redacted non-object diagnostic]')
            kinds.append('non-object-json')
            continue
        safe = {}
        hidden = 0
        for key, item in value.items():
            if key == 'leaseHeld' and isinstance(item, bool):
                safe[key] = item
            elif key in PUBLIC_VALUES and isinstance(item, str) and item in PUBLIC_VALUES[key]:
                safe[key] = item
            else:
                hidden += 1
        if hidden:
            safe['redactedFields'] = hidden
        rendered.append(json.dumps(safe, separators=(',', ':')))
        kinds.append('object-json')
    text_bytes = '\n'.join(rendered).encode('utf-8')
    # JSON escapes can decode into an otherwise-public enum that is itself a credential.
    for form in sorted(forms, key=len, reverse=True):
        text_bytes = text_bytes.replace(form, b'[redacted]')
    text = text_bytes.decode('utf-8')
    return {'stderrText': text[:TEXT_LIMIT], 'stderrTextTruncated': len(data) > INPUT_LIMIT or len(text) > TEXT_LIMIT,
            'stderrLineKinds': kinds[:64], 'stderrBytesObserved': len(data),
            'stderrMalformedLineMetadata': malformed,
            'stderrMalformedLineMetadataTruncated': metadata_truncated}


def reader_states(process):
    # Windows communicate() reader threads can outlive an already-exited process.
    states = {}
    for stream in ('stdout', 'stderr'):
        thread = getattr(process, stream + '_thread', None)
        states[stream] = {'present': thread is not None,
                          'complete': None if thread is None else not thread.is_alive()}
    return states


def completed_buffer(process, stream):
    thread = getattr(process, stream + '_thread', None)
    buffer = getattr(process, '_' + stream + '_buff', None)
    if thread is not None and not thread.is_alive() and buffer:
        return b''.join(buffer)
    return None


def executable_digest(process):
    try:
        with Path(process.args[0]).open('rb') as source:
            digest = hashlib.sha256()
            for chunk in iter(lambda: source.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    except (OSError, TypeError, ValueError):
        return None


def capture_failure(case, process, started, error, *, stdout=None, stderr=None,
                    prefix=b'', credential=None, timeout=None):
    observed = time.monotonic()
    poll = process.poll()
    readers = reader_states(process)
    if stdout is None:
        stdout = getattr(error, 'output', None)
        if stdout is None:
            stdout = completed_buffer(process, 'stdout')
    if stderr is None:
        stderr = getattr(error, 'stderr', None)
        if stderr is None:
            stderr = completed_buffer(process, 'stderr')
    evidence = {'case': case, 'type': type(error).__name__, 'pid': process.pid,
                'executableSha256': executable_digest(process),
                'observedUnixSeconds': round(time.time(), 3),
                'elapsedSeconds': round(observed - started, 3), 'timeoutSeconds': timeout,
                'pollAtFailure': poll, 'ownedChildExitedAtFailure': poll is not None,
                'readersAtFailure': readers, 'stdoutAvailable': stdout is not None,
                'stdoutBytes': None if stdout is None else len(stdout),
                'stdoutSha256': None if stdout is None else hashlib.sha256(stdout).hexdigest(),
                'stdoutComplete': readers['stdout']['complete'],
                'stderrAvailable': stderr is not None or bool(prefix),
                'stderrComplete': readers['stderr']['complete']}
    evidence.update(diagnostic_text(prefix + (stderr or b''), credential))
    if isinstance(error, json.JSONDecodeError):
        evidence['jsonError'] = {'line': error.lineno, 'column': error.colno, 'position': error.pos}
    return evidence


def finish_cleanup(evidence, process, started, kill_requested, cleanup_error=None, *, credential=None):
    poll = process.poll()
    evidence['cleanup'] = {'killRequested': kill_requested, 'exit': poll,
                           'ownedChildTerminal': poll is not None,
                           'elapsedSeconds': round(time.monotonic() - started, 3),
                           'errorType': None if cleanup_error is None else type(cleanup_error).__name__,
                           'readers': reader_states(process)}
    out = completed_buffer(process, 'stdout')
    err = completed_buffer(process, 'stderr')
    evidence['cleanup']['stdoutAvailable'] = out is not None
    evidence['cleanup']['stdoutBytes'] = None if out is None else len(out)
    evidence['cleanup']['stdoutSha256'] = None if out is None else hashlib.sha256(out).hexdigest()
    evidence['cleanup']['stderrAvailable'] = err is not None
    if err is not None:
        evidence['cleanup'].update(diagnostic_text(err, credential))


def persist_failures(path, failures):
    try:
        path.write_text(json.dumps({'failureEvidence': failures}, indent=2), encoding='utf-8')
    except OSError as error:
        # Do not replace the assertion/timeout with an evidence-write exception.
        failures[-1]['evidenceWriteErrorType'] = type(error).__name__
