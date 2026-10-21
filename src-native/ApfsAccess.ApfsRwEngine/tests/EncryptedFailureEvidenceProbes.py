"""Diagnostic-only privacy probes. Uses fake credentials and launches no child."""
import argparse
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import time
from types import SimpleNamespace
import unittest

from EncryptedFailureEvidence import (
    INPUT_LIMIT, capture_failure, diagnostic_text, finish_cleanup, persist_failures,
)


class FailureEvidenceProbes(unittest.TestCase):
    root = None

    def assert_private(self, result, fragments):
        serialized = json.dumps(result).encode()
        for fragment in fragments:
            self.assertNotIn(fragment, serialized)
            self.assertNotIn(hashlib.sha256(fragment).hexdigest().encode(), serialized)
        for item in result['stderrMalformedLineMetadata']:
            self.assertLessEqual(set(item), {'line', 'byteLength', 'category', 'truncated', 'whitespaceCounts'})

    def test_blank_cr_lf_and_tab_lines(self):
        data = b'\r\n\n\r\t \t\r\n\t\n'
        result = diagnostic_text(data)
        items = result['stderrMalformedLineMetadata']
        self.assertEqual([i['category'] for i in items],
                         ['empty', 'empty', 'empty', 'ascii-whitespace-only', 'ascii-whitespace-only'])
        self.assertEqual([i['byteLength'] for i in items], [0, 0, 0, 3, 1])
        self.assertEqual([i['line'] for i in items], [1, 2, 3, 4, 5])
        self.assertEqual(items[3]['whitespaceCounts']['tab'], 2)
        self.assertEqual(items[3]['whitespaceCounts']['space'], 1)
        self.assertEqual(items[4]['whitespaceCounts']['tab'], 1)
        self.assertEqual(result['stderrLineKinds'], ['malformed-json'] * 5)
        self.assertFalse(result['stderrMalformedLineMetadataTruncated'])

    def test_other_ascii_whitespace_classes(self):
        result = diagnostic_text(b' \t\v\f\n')
        item = result['stderrMalformedLineMetadata'][0]
        self.assertEqual(item['category'], 'ascii-whitespace-only')
        self.assertEqual(item['whitespaceCounts'],
                         {'space': 1, 'tab': 1, 'cr': 0, 'lf': 0, 'verticalTab': 1, 'formFeed': 1})

    def test_public_enums_and_unknown_fields_stay_redacted(self):
        fragment = b'FAKE_PRIVATE_UNKNOWN_FIELD'
        result = diagnostic_text(b'{"state":"Locked","leaseHeld":true,"extra":"' + fragment + b'"}\n')
        self.assertEqual(json.loads(result['stderrText']),
                         {'state': 'Locked', 'leaseHeld': True, 'redactedFields': 1})
        self.assertEqual(result['stderrMalformedLineMetadata'], [])
        self.assert_private(result, [fragment])

    def test_malformed_credential_length_precedes_redaction(self):
        credential = b'PUBLIC_FAKE_CREDENTIAL_123456789'
        data = b'not-json:' + credential + b'\t\x00'
        result = diagnostic_text(data, credential)
        item = result['stderrMalformedLineMetadata'][0]
        self.assertEqual(item['byteLength'], len(data))
        self.assertEqual(item['category'], 'non-json-text')
        self.assertNotIn('whitespaceCounts', item)
        self.assertEqual(result['stderrText'], '[redacted malformed diagnostic]')
        self.assert_private(result, [credential, data])

    def test_malformed_encoded_credential_forms_are_opaque(self):
        credential = b'PUBLIC_FAKE_"\\\t_CREDENTIAL'
        forms = {credential, credential.hex().encode(), credential.hex().upper().encode(),
                 base64.b64encode(credential), json.dumps(credential.decode())[1:-1].encode()}
        for form in forms:
            with self.subTest(formLength=len(form)):
                data = b'broken[' + form + b']'
                result = diagnostic_text(data, credential)
                self.assertEqual(result['stderrMalformedLineMetadata'][0]['byteLength'], len(data))
                self.assert_private(result, list(forms) + [data])

    def test_invalid_utf8_and_binary_control_bytes_are_opaque(self):
        credential = b'PUBLIC_FAKE_BINARY_CREDENTIAL'
        data = b'\xff\xfe\x00\x01' + credential + b'\t'
        result = diagnostic_text(data, credential)
        item = result['stderrMalformedLineMetadata'][0]
        self.assertEqual(item['category'], 'non-utf8')
        self.assertEqual(item['byteLength'], len(data))
        self.assertNotIn('whitespaceCounts', item)
        self.assert_private(result, [credential, data])

    def test_interleaved_json_stays_malformed(self):
        data = b'{"state":"Lock{"state":"Unlocking"}ed"}\n'
        result = diagnostic_text(data)
        self.assertEqual(result['stderrMalformedLineMetadata'][0]['category'], 'non-json-text')
        self.assertEqual(result['stderrLineKinds'], ['malformed-json'])
        self.assertNotIn('whitespaceCounts', result['stderrMalformedLineMetadata'][0])
        with self.assertRaises(json.JSONDecodeError):
            json.loads(data.splitlines()[0])

    def test_multiline_credential_suppresses_whitespace_counts(self):
        credential = b'PUBLIC_FAKE_MULTILINE\n\t '
        result = diagnostic_text(b'broken:' + credential + b'\n', credential)
        self.assertEqual(result['stderrMalformedLineMetadata'][1]['category'], 'ascii-whitespace-only')
        self.assertTrue(all('whitespaceCounts' not in i for i in result['stderrMalformedLineMetadata']))
        self.assert_private(result, [credential])

    def test_whitespace_credential_suppresses_counts(self):
        result = diagnostic_text(b'\t \t\n', b'\t \t')
        self.assertEqual(result['stderrMalformedLineMetadata'][0]['category'], 'ascii-whitespace-only')
        self.assertNotIn('whitespaceCounts', result['stderrMalformedLineMetadata'][0])

    def test_escaped_credential_matching_public_enum_stays_redacted(self):
        result = diagnostic_text(b'{"state":"\\u004c\\u006f\\u0063\\u006b\\u0065\\u0064"}', b'Locked')
        self.assert_private(result, [b'Locked'])
        self.assertIn('[redacted]', result['stderrText'])
        self.assertEqual(result['stderrMalformedLineMetadata'], [])

    def test_non_object_json_is_not_relabelled(self):
        result = diagnostic_text(b'[]\n42\n"PUBLIC_FAKE_UNKNOWN_VALUE"\n')
        self.assertEqual(result['stderrLineKinds'], ['non-object-json'] * 3)
        self.assertEqual(result['stderrMalformedLineMetadata'], [])
        self.assert_private(result, [b'PUBLIC_FAKE_UNKNOWN_VALUE'])

    def test_line_limit_and_input_limit_remain_bounded(self):
        result = diagnostic_text(b'\n' * 70)
        self.assertEqual(len(result['stderrMalformedLineMetadata']), 64)
        self.assertEqual(result['stderrMalformedLineMetadata'][-1]['line'], 64)
        self.assertTrue(result['stderrMalformedLineMetadataTruncated'])
        result = diagnostic_text(b'\t' * (INPUT_LIMIT + 256))
        item = result['stderrMalformedLineMetadata'][0]
        self.assertEqual(item['byteLength'], INPUT_LIMIT)
        self.assertTrue(item['truncated'])
        self.assertNotIn('whitespaceCounts', item)
        self.assertTrue(result['stderrMalformedLineMetadataTruncated'])
        self.assertTrue(result['stderrTextTruncated'])
        self.assertEqual(result['stderrBytesObserved'], INPUT_LIMIT + 256)

    def test_valid_status_then_malformed_line_has_original_index(self):
        data = b'{"state":"Locked"}\n\t\r\n'
        result = diagnostic_text(data)
        self.assertEqual(result['stderrMalformedLineMetadata'][0]['line'], 2)
        self.assertEqual(result['stderrLineKinds'], ['object-json', 'malformed-json'])

    def test_capture_cleanup_and_persistence_preserve_failure(self):
        credential = b'PUBLIC_FAKE_CAPTURE_CREDENTIAL'
        unknown = b'broken:' + credential
        data = b'{"state":"Locked"}\n\r\n' + unknown + b'\n'
        done = SimpleNamespace(is_alive=lambda: False)
        process = SimpleNamespace(pid=123, args=[__file__], poll=lambda: 5,
                                  stdout_thread=done, stderr_thread=done,
                                  _stdout_buff=[b''], _stderr_buff=[data])
        try:
            # Same unmodified splitlines/json.loads check used by acceptance.
            for line in data.splitlines():
                json.loads(line)
        except json.JSONDecodeError as error:
            evidence = capture_failure('public-fake-malformed', process, time.monotonic(), error,
                                       stdout=b'', stderr=data, credential=credential)
        else:
            self.fail('Malformed line unexpectedly accepted')
        finish_cleanup(evidence, process, time.monotonic(), False, credential=credential)
        self.assertEqual(evidence['type'], 'JSONDecodeError')
        self.assertEqual(evidence['pollAtFailure'], 5)
        self.assertEqual(evidence['jsonError']['position'], 0)
        self.assertEqual(evidence['cleanup']['exit'], 5)
        self.assertFalse(evidence['cleanup']['killRequested'])
        for item in (evidence, evidence['cleanup']):
            self.assertEqual([i['category'] for i in item['stderrMalformedLineMetadata']],
                             ['empty', 'non-json-text'])
            self.assert_private(item, [credential, unknown])
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            path = Path(directory) / 'failure-evidence.json'
            persist_failures(path, [evidence])
            persisted = json.loads(path.read_text(encoding='utf-8'))['failureEvidence'][0]
            self.assertEqual(persisted['type'], 'JSONDecodeError')
            self.assert_private(persisted, [credential, unknown])
            (self.root / 'safe-capture-example.json').write_text(json.dumps(persisted, indent=2), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--root', required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if root.drive.lower() != 'd:':
        raise ValueError('Probe artifacts must remain on D:')
    root.mkdir(parents=True, exist_ok=True)
    os.environ['TEMP'] = os.environ['TMP'] = str(root)
    FailureEvidenceProbes.root = root
    stream = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(FailureEvidenceProbes)
    result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
    summary = {'testsRun': result.testsRun, 'failures': len(result.failures),
               'errors': len(result.errors), 'passed': result.wasSuccessful()}
    (root / 'probe-results.json').write_text(json.dumps(summary, indent=2), encoding='utf-8')
    (root / 'probe-results.txt').write_text(stream.getvalue(), encoding='utf-8')
    print(json.dumps(summary))
    return 0 if result.wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
