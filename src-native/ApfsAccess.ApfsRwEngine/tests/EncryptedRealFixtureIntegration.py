"""Opt-in Windows production reads of hash-pinned, public Apple-made images.

Acquire fixtures and their public credential notes outside the repository.
Credentials enter only the child-owned protected stdin frame. Evidence stores
selectors, statuses and digests, never credentials, wrapped keys or file bytes.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
from EncryptedFailureEvidence import capture_failure, finish_cleanup, persist_failures


def digest(path):
    result = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixtures", required=True)
    parser.add_argument("--root", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--baseline-tool")
    parser.add_argument("--profile", choices=["apple-native", "independent-dfvfs"])
    args = parser.parse_args()
    root = Path(args.root).resolve()
    if root.drive.lower() != "d:":
        raise ValueError("Evidence must stay on D:")
    root.mkdir(parents=True, exist_ok=True)
    os.environ["TEMP"] = os.environ["TMP"] = str(root)
    fixtures = Path(args.fixtures).resolve()
    profiles = [
        {"name": "apple-native", "image": "native-filevault.raw", "offset": 0,
         "size": 134176768, "imageSha256": "1a46eb22cdab37ae553c5c70b7b172419c9cda7285de7f5b4fd3129c73e29171",
         "notes": "native-filevault.raw.gz.source-notes", "pattern": r"\| Password \| `([^`]+)`",
         "expected": b"APFS-FILEVAULT-GROUND-TRUTH-MARKER-0123456789\n"},
        {"name": "independent-dfvfs", "image": "dfvfs-apfs-encrypted.dmg", "offset": 20480,
         "size": 4153344, "imageSha256": "33fe6f183aeb1a95fec68efdab17d59aedbad3d8ef1a117d411117376d9d8485",
         "notes": "dfvfs-apfs-encrypted.dmg.source-notes", "pattern": r'_APFS_PASSWORD = "([^"]+)"',
         "expected": b"This is another file.\n", "inode": 21},
    ]
    rows = []
    failure_evidence = []
    if args.profile:
        profiles = [p for p in profiles if p["name"] == args.profile]

    def run(label, command, credential=None, frame_suffix=b""):
        started = time.monotonic()
        startup = subprocess.STARTUPINFO()
        startup.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        frame = None if credential is None else b"APC1" + struct.pack("<I", len(credential)) + credential + frame_suffix
        with subprocess.Popen(command, stdin=subprocess.PIPE if frame is not None else None,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              startupinfo=startup, close_fds=True) as child:
            try:
                out, err = child.communicate(input=frame, timeout=45)
            except subprocess.TimeoutExpired:
                child.kill()
                child.communicate()
                raise
            except BaseException:
                child.kill()
                raise
        result = subprocess.CompletedProcess(command, child.returncode, out, err)
        try:
            if credential and (credential in result.stdout or credential in result.stderr):
                raise AssertionError("credential exposed in child output")
            for line in result.stderr.splitlines():
                state = json.loads(line)
                if state.get("state") not in ("Locked", "Unlocking"):
                    raise AssertionError("non-public diagnostic output")
            rows.append({"case": label, "exit": result.returncode,
                         "elapsedSeconds": round(time.monotonic() - started, 3),
                         "stdoutBytes": len(result.stdout), "stdoutSha256": hashlib.sha256(result.stdout).hexdigest(),
                         "stderr": result.stderr.decode("utf-8", "strict").strip()})
        except Exception as error:
            evidence = capture_failure(label, child, started, error, stdout=out, stderr=err,
                                       credential=credential)
            finish_cleanup(evidence, child, started, False, credential=credential)
            failure_evidence.append(evidence)
            persist_failures(root / 'failure-evidence.json', failure_evidence)
            raise
        return result

    failure = None
    try:
        for p in profiles:
            image = fixtures / p["image"]
            if digest(image) != p["imageSha256"]:
                raise AssertionError(p["name"] + " source hash")
            notes = (fixtures / p["notes"]).read_text(encoding="utf-8-sig")
            credential = re.search(p["pattern"], notes).group(1).encode("utf-8")
            base = [str(args.tool), "--image", str(image), "--store-offset", str(p["offset"]),
                    "--store-size", str(p["size"]), "--volume-oid", "1026", "--bag-length", "includes-header"]
            selected = run(p["name"] + ":locked-selectors", base + ["--mode", "selectors"])
            if selected.returncode:
                raise AssertionError(p["name"] + " locked selectors")
            selection = json.loads(selected.stdout)
            if selection["state"] != "Locked" or selection["writeAuthorization"] or selection["persistentUnlockedMount"]:
                raise AssertionError("selection granted unsupported authority")
            if selection["containerBagOid"] != 0 or selection["volumeBagOid"] != 0 or len(selection["users"]) != 1:
                raise AssertionError("exact special-object identities / selected user")
            (root / (p["name"] + "-selectors.json")).write_text(json.dumps(selection, indent=2), encoding="utf-8")
            options = {"source-id": selection["sourceId"], "container-uuid": selection["containerUuid"],
                       "volume-uuid": selection["volumeUuid"], "checkpoint-xid": selection["checkpointXid"],
                       "user-uuid": selection["users"][0], "container-bag-oid": selection["containerBagOid"],
                       "container-bag-xid": selection["containerBagXid"], "volume-bag-oid": selection["volumeBagOid"],
                       "volume-bag-xid": selection["volumeBagXid"]}
            exact = base[:]
            for key, value in options.items():
                exact += ["--" + key, str(value)]
            if args.baseline_tool:
                red = run(p["name"] + ":baseline-real-unlock", [str(args.baseline_tool)] + exact[1:] + ["--mode", "inspect"], credential)
                if red.returncode != 5 or b'"InvalidArgument"' not in red.stderr:
                    raise AssertionError("baseline did not reproduce exact zero-OID refusal")
            inspected = run(p["name"] + ":production-inspect", exact + ["--mode", "inspect"], credential)
            if inspected.returncode:
                raise AssertionError(p["name"] + " production inspect")
            inventory = json.loads(inspected.stdout)
            expected = p["expected"]
            files = inventory["files"]
            candidates = [p["inode"]] if "inode" in p else [int(f["inode"]) for f in files if int(f["size"]) == len(expected)]
            if len(candidates) != 1:
                raise AssertionError("known plaintext exact inode selection")
            inode = candidates[0]
            command = exact + ["--mode", "read", "--inode", str(inode), "--offset", "0", "--length", str(len(expected)), "--binary-stdout"]
            read = run(p["name"] + ":production-exact-read", command, credential)
            if read.returncode or read.stdout != expected:
                raise AssertionError(p["name"] + " independent known plaintext mismatch")
            rows[-1]["expectedSha256"] = hashlib.sha256(expected).hexdigest()
            wrong = run(p["name"] + ":wrong-credential", command, b"incorrect-public-fixture-credential")
            if wrong.returncode != 5 or wrong.stdout or b'"CredentialOrKeyMismatch"' not in wrong.stderr:
                raise AssertionError("wrong credential refusal")
            wrong_oid = command[:]
            wrong_oid[wrong_oid.index("--container-bag-oid") + 1] = "356" if p["name"] == "apple-native" else "88"
            refused = run(p["name"] + ":paddr-is-not-oid", wrong_oid, credential)
            if refused.returncode != 5 or refused.stdout or b'"IdentityMismatch"' not in refused.stderr:
                raise AssertionError("keybag paddr fallback admitted")
            for offset, length in [(0, 1), (5, len(expected)-7), (len(expected)-1, 1), (len(expected), 0)]:
                partial = command[:]
                partial[partial.index("--offset") + 1] = str(offset)
                partial[partial.index("--length") + 1] = str(length)
                read = run(p["name"] + f":range-{offset}-{length}", partial, credential)
                answer = expected[offset:offset+length]
                rows[-1]["expectedSha256"] = hashlib.sha256(answer).hexdigest()
                if read.returncode or read.stdout != answer:
                    raise AssertionError("partial production plaintext read")
            over = command[:]
            over[over.index("--offset")+1] = str(len(expected))
            over[over.index("--length")+1] = "1"
            refused = run(p["name"] + ":over-eof", over, credential)
            if refused.returncode != 7 or refused.stdout or b'"InvalidArgument"' not in refused.stderr:
                raise AssertionError("over-EOF publication")
            refused = run(p["name"] + ":trailing-credential-frame", command, credential, b"x")
            if refused.returncode != 4 or refused.stdout:
                raise AssertionError("credential framing accepted trailing bytes")
            root_metadata = run(p["name"] + ":root-metadata", exact + ["--mode", "metadata", "--inode", "2"], credential)
            if root_metadata.returncode:
                raise AssertionError("root metadata unavailable")
            metadata = json.loads(root_metadata.stdout)
            if metadata["posixMode"] & 0o170000 != 0o040000 or metadata["internalFlags"] != 0x8000 or metadata["parent"] != 2:
                raise AssertionError("known root metadata profile")
            private = run(p["name"] + ":private-directory-hidden", exact + ["--mode", "metadata", "--inode", "3"], credential)
            if private.returncode != 7 or private.stdout or b'"FileNotFound"' not in private.stderr:
                raise AssertionError("reserved private directory exposed")
            if p["name"] == "independent-dfvfs":
                link_metadata = run(p["name"] + ":symlink-metadata", exact + ["--mode", "metadata", "--inode", "22"], credential)
                if link_metadata.returncode:
                    raise AssertionError("symlink metadata unavailable")
                metadata = json.loads(link_metadata.stdout)
                if metadata["posixMode"] & 0o170000 != 0o120000 or metadata["symlinkFollowed"]:
                    raise AssertionError("symlink was not metadata-only")
                target = run(p["name"] + ":symlink-embedded-target", exact + ["--mode", "xattr", "--inode", "22", "--xattr", "com.apple.fs.symlink", "--binary-stdout"], credential)
                if target.returncode or not target.stdout.endswith(b"\0") or metadata["size"] != len(target.stdout)-1:
                    raise AssertionError("symlink embedded target framing")
                link_read = command[:]
                link_read[link_read.index("--inode")+1] = "22"
                refused = run(p["name"] + ":symlink-file-read-refused", link_read, credential)
                if refused.returncode != 7 or refused.stdout or b'"FileNotFound"' not in refused.stderr:
                    raise AssertionError("symlink followed as file data")
            if digest(image) != p["imageSha256"]:
                raise AssertionError("source changed during read-only gate")
    except Exception as error:
        failure = str(error)
    report = {"pass": failure is None, "failure": failure, "rows": rows,
              "failureEvidence": failure_evidence,
              "toolSha256": digest(Path(args.tool)),
              "images": [{"profile": p["name"], "sha256": digest(fixtures / p["image"]),
                          "expectedSha256": p["imageSha256"]} for p in profiles],
              "acceptance": "ProductionWindowsImageReadOnly" if failure is None else "Failed",
              "physicalMount": False, "encryptedWriter": False, "macOSAcceptance": False}
    (root / "result.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 1 if failure else 0


if __name__ == "__main__":
    raise SystemExit(main())
