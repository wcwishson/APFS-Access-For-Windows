"""Windows real-process regression using a caller-supplied genuine image.

Only the supplied Observer is executed, in collect/verify modes. No repair,
service, host, drive/device discovery, mount, or process termination is used.
All outputs and copied images must live under a fresh D: root.
"""

import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


def sha(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def save(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, indent=2), encoding="utf-8")


def need(condition, detail):
    if not condition:
        raise AssertionError(detail)


def run(observer, args, directory, label):
    started = time.monotonic()
    process = subprocess.Popen([str(observer), *args], stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # These bounded, read-only image operations exit naturally. Do not kill a
    # process on timeout: retain its PID and let the caller reconcile it.
    try:
        stdout, stderr = process.communicate(timeout=70)
    except subprocess.TimeoutExpired:
        save(directory / (label + ".timeout.json"), {"pid": process.pid, "terminated": False})
        raise RuntimeError("Observer deadline exceeded; no termination attempted")
    (directory / (label + ".stdout.bin")).write_bytes(stdout)
    (directory / (label + ".stderr.bin")).write_bytes(stderr)
    safe_args = []
    for arg in args:
        try:
            arg.encode("utf-8", errors="strict")
            safe_args.append(arg)
        except UnicodeError:
            safe_args.append("<invalid UTF-16: " + ",".join(hex(ord(c)) for c in arg) + ">")
    record = {"label": label, "pid": process.pid, "exitCode": process.returncode,
              "arguments": safe_args, "elapsedSeconds": time.monotonic() - started,
              "stdoutSha256": hashlib.sha256(stdout).hexdigest(),
              "stderrSha256": hashlib.sha256(stderr).hexdigest()}
    save(directory / (label + ".process.json"), record)
    return record, stdout, stderr


def validate(document, mode, image, digest, selected):
    source = document["source"]
    need(source["kind"] == "image" and source["path"] == str(image), "exact Unicode source path")
    if mode == "collect":
        need(document["format"] == "apfs-access-raw-evidence" and document["version"] == 1, "catalog wire version")
        need(document["mode"] == "collect" and document["synthetic"] is False, "catalog mode")
        need(source["hashScope"] == "full" and source["sha256"] == digest, "catalog full source hash")
        topology = document["topology"]
        need(any(d["deviceIdentifier"] == str(image) for d in topology["disks"]), "catalog disk path")
        need(any(c["uuid"] == selected["containerUuid"] for c in topology["containers"]), "catalog container")
        need(any(v["uuid"] == selected["volumeUuid"] and v["objectId"] == selected["volumeOid"]
                 for v in topology["volumes"]), "catalog volume identity")
    else:
        need(document["format"] == "apfs-access-verification" and document["readOnly"] is True, "verification wire")
        need(source["lease"] == "windows-read-deny-write-delete" and source["identity"], "held image lease")
        scope = document["requestedScope"]
        for key, value in selected.items():
            need(str(scope[key]) == value, "exact verification scope: " + key)
        need(scope["requireWholeVolume"] is False and scope["requirePayloadContentHashes"] is False, "unchanged coverage flags")
        need(document["outcome"] == 1 and not document["findings"], "covered metadata Complete")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--observer", required=True, type=Path)
    parser.add_argument("--preflight", required=True, type=Path)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--label", required=True, choices=["RED", "GREEN"])
    args = parser.parse_args()
    need(os.name == "nt", "Windows wide process arguments required")
    root = args.root.absolute()
    need(root.drive.upper() == "D:" and not root.exists(), "fresh private D: output root required")
    root.mkdir(parents=True)
    env_root = root / "temp"
    env_root.mkdir()
    for key in ("TEMP", "TMP", "HOME", "DOTNET_CLI_HOME", "NUGET_SCRATCH"):
        os.environ[key] = str(env_root)
    config = json.loads(args.preflight.read_text(encoding="utf-8-sig"))
    fixture = Path(config["fixtureSource"])
    source_hash, observer_hash = sha(fixture), sha(args.observer)
    need(source_hash == config["fixtureSha256"].lower(), "pinned genuine fixture hash")
    selected = {"containerUuid": config["fixtureMint"]["containerUuid"],
                "volumeUuid": config["fixtureMint"]["volumeUuid"],
                "volumeOid": config["fixtureMint"]["volumeOid"],
                "checkpointXid": config["fixtureMint"]["checkpointXid"],
                "storeOffsetBytes": config["storeOffsetBytes"],
                "storeSizeBytes": config["fixtureMint"]["storeSizeBytes"]}
    cases = [("ascii", "ascii", "fixture.apfsimg"),
             ("chinese", "\u4e2d\u6587\u8def\u5f84", "\u56fe\u50cf.apfsimg"),
             ("supplementary", "Unicode_\U0001f680_path", "image_\U0001f680.apfsimg")]
    checks, copies = [], []
    for case, dirname, filename in cases:
        directory = root / dirname
        directory.mkdir()
        image = directory / filename
        shutil.copyfile(fixture, image)
        copies.append(image)
        for mode in ("collect", "verify"):
            arguments = ["--image", str(image), "--mode", mode]
            if mode == "collect":
                arguments += ["--profile", "unicode-path-regression", "--device-id", "unicode-proof"]
            else:
                for flag, key in [("container-uuid", "containerUuid"), ("volume-uuid", "volumeUuid"),
                                  ("volume-oid", "volumeOid"), ("checkpoint-xid", "checkpointXid"),
                                  ("store-offset-bytes", "storeOffsetBytes"), ("store-size-bytes", "storeSizeBytes")]:
                    arguments += ["--" + flag, selected[key]]
            for publish in (False, True):
                label = case + "-" + mode + ("-out" if publish else "-stdout")
                output = directory / ("\u8bc1\u636e_\U0001f680_" + mode + ".json") if publish else None
                record, stdout, stderr = run(args.observer, arguments + (["--out", str(output)] if output else []), directory, label)
                try:
                    need(record["exitCode"] == 0, "exit 0; stderr=" + stderr.decode("utf-8", errors="replace"))
                    raw = output.read_bytes() if output else stdout
                    if output:
                        need(not stdout, "--out keeps stdout empty")
                    need(len(raw) <= 64 * 1024 * 1024, "bounded output")
                    document = json.loads(raw.decode("utf-8", errors="strict"))
                    validate(document, mode, image, source_hash, selected)
                    record["passed"] = True
                except (AssertionError, UnicodeError, ValueError, KeyError, OSError) as error:
                    record.update(passed=False, error=str(error))
                need(sha(image) == source_hash, "input image bytes changed")
                checks.append(record)
            label = case + "-" + mode + "-refuse-input-output-alias"
            record, stdout, stderr = run(args.observer, arguments + ["--out", str(image)], directory, label)
            record["passed"] = record["exitCode"] == 2 and b"refusing to overwrite observer input" in stderr
            need(sha(image) == source_hash, "alias refusal must preserve image")
            checks.append(record)
    for code in (0xD800, 0xDC00):
        record, stdout, stderr = run(args.observer, ["--image", chr(code), "--mode", "collect", "--profile", "unicode-path-regression"], root, "invalid-utf16-" + hex(code))
        record["passed"] = record["exitCode"] == 2 and b"argument is not valid UTF-16" in stderr and not stdout
        checks.append(record)
    need(sha(fixture) == source_hash and sha(args.observer) == observer_hash, "original inputs unchanged")
    unchanged = all(sha(image) == source_hash for image in copies)
    report = {"label": args.label, "acp": ctypes.windll.kernel32.GetACP(),
              "observer": str(args.observer), "observerSha256": observer_hash,
              "fixture": str(fixture), "fixtureSha256": source_hash, "imagesUnchanged": unchanged,
              "checks": checks, "passed": sum(c["passed"] for c in checks), "total": len(checks),
              "success": all(c["passed"] for c in checks), "nativeBuilds": 0, "mounts": 0}
    save(root / "result.json", report)
    print(json.dumps({k: report[k] for k in ("label", "acp", "passed", "total", "success", "imagesUnchanged")}, ensure_ascii=True))
    return 0 if report["success"] else 1


if __name__ == "__main__":
    sys.exit(main())
