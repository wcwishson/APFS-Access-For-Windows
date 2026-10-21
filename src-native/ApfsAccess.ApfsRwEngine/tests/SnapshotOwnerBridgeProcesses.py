"""Owner-gated SnapshotImage process gate (Task 7).

Drives the built SnapshotImage.exe end to end over file-backed fixtures
(positional CLI: list|recover IMAGE CONTAINER_UUID VOLUME_UUID OID JOURNAL_DIR,
create ... OID SOURCE_XID NAME TIME_NS INUM JOURNAL_DIR,
delete ... OID SOURCE_XID SNAPSHOT_XID NAME APSB OMAP OMAP_TREE ROOT_OID
ROOT_BLOCK EXTENTREF TIME_NS JOURNAL_DIR):
positive create/list/delete/recover, exact delete-identity fields, refusal
paths (wrong container, stale XID, wrong snapshot identity, substituted
clean journal, active image owner) with image/journal byte invariance.
No macOS/Fusion/physical/mount claims.

Usage:
  python SnapshotOwnerBridgeProcesses.py --root D:\\work --tool SnapshotImage.exe \
      --fixture-builder SnapshotOwnerBridgeTests.exe
"""
import argparse
import ctypes
import ctypes.wintypes
import hashlib
import os
import re
import subprocess
import sys

CHECKS = [0]


def check(value, message):
    CHECKS[0] += 1
    if not value:
        raise AssertionError(message)


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(tool, args, timeout=120):
    completed = subprocess.run(
        [tool] + args, capture_output=True, text=True, timeout=timeout)
    return completed.returncode, completed.stdout, completed.stderr


def parse_list(stdout):
    header, entries = {}, []
    for line in stdout.splitlines():
        match = re.match(r"container=(\S+) volume=(\S+) oid=(\d+) source_xid=(\d+) count=(\d+)", line)
        if match:
            header = {
                "container": match.group(1), "volume": match.group(2),
                "oid": int(match.group(3)), "xid": int(match.group(4)),
                "count": int(match.group(5)),
            }
            continue
        match = re.match(
            r"source_xid=(\d+) snapshot_xid=(\d+) name=\"([^\"]*)\" apsb=(\d+) "
            r"omap=(\d+) omap_tree=(\d+) root_oid=(\d+) root_block=(\d+) extentref=(\d+)", line)
        if match:
            entries.append({
                "source_xid": int(match.group(1)), "snapshot_xid": int(match.group(2)),
                "name": match.group(3), "apsb": int(match.group(4)),
                "omap": int(match.group(5)), "omap_tree": int(match.group(6)),
                "root_oid": int(match.group(7)), "root_block": int(match.group(8)),
                "extentref": int(match.group(9)),
            })
    return header, entries


def hold_exclusive(path):
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateFileW.restype = ctypes.wintypes.HANDLE
    kernel32.CreateFileW.argtypes = [ctypes.wintypes.LPCWSTR, ctypes.wintypes.DWORD,
                                     ctypes.wintypes.DWORD, ctypes.wintypes.LPVOID,
                                     ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                                     ctypes.wintypes.HANDLE]
    invalid = ctypes.wintypes.HANDLE(-1).value
    handle = kernel32.CreateFileW(str(path), 0xC0000000, 0, None, 3, 0x80, None)
    if handle == invalid or not handle:
        raise AssertionError("could not hold image exclusively for active-owner probe")
    return kernel32, handle


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--fixture-builder", required=True)
    options = parser.parse_args()
    root = os.path.abspath(options.root)
    os.makedirs(root, exist_ok=True)
    image = os.path.join(root, "bridge-proc.apfs")
    journals = os.path.join(root, "journals")

    out = subprocess.run(
        [options.fixture_builder, "write-fixture", image],
        capture_output=True, text=True, timeout=120, cwd=root)
    check(out.returncode == 0, "fixture builder: " + out.stderr[-500:])
    container = re.search(r"container=([0-9a-f]{32})", out.stdout).group(1)
    volume_uuid = re.search(r"volume=101:([0-9a-f]{32})", out.stdout).group(1)
    base = [image, container, volume_uuid, "101"]

    def snap_list(journal_dir=journals):
        return run(options.tool, ["list"] + base + [journal_dir])

    code, stdout, _ = snap_list()
    check(code == 0, "list exit 0")
    header, entries = parse_list(stdout)
    check(header.get("count") == 0 and entries == [], "genesis list empty")
    xid = str(header["xid"])

    code, stdout, _ = run(options.tool, ["create"] + base +
                           [xid, "proc-one", "1700000000000000000", "0", journals])
    check(code == 0 and "Published" in stdout, "create proc-one: " + stdout[-300:])
    code, stdout, _ = snap_list()
    header, entries = parse_list(stdout)
    check(code == 0 and len(entries) == 1 and entries[0]["name"] == "proc-one", "one snapshot listed")
    first = entries[0]
    for field in ("apsb", "omap", "omap_tree", "root_oid", "root_block", "extentref"):
        check(first[field] > 0, "delete identity field present: " + field)
    xid = str(header["xid"])

    code, stdout, _ = run(options.tool, ["create"] + base +
                           [xid, "proc-two", "1700000000000000001", "0", journals])
    check(code == 0, "create proc-two")
    code, stdout, _ = snap_list()
    header, entries = parse_list(stdout)
    check(len(entries) == 2, "two snapshots listed")
    oldest = min(entries, key=lambda item: item["snapshot_xid"])
    check(oldest["name"] == "proc-one", "oldest identified")
    xid = str(header["xid"])

    def delete_args(entry, source_xid):
        return (["delete"] + base + [source_xid, str(entry["snapshot_xid"]), entry["name"]] +
                [str(entry[field]) for field in
                 ("apsb", "omap", "omap_tree", "root_oid", "root_block", "extentref")] +
                ["1700000000000000002", journals])

    tampered = delete_args(dict(oldest, root_block=oldest["root_block"] + 1), xid)
    code, _, _ = run(options.tool, tampered)
    check(code != 0, "wrong snapshot identity refused")

    code, stdout, _ = run(options.tool, delete_args(oldest, xid))
    check(code == 0 and "Published" in stdout, "delete oldest: " + stdout[-300:])
    code, stdout, _ = snap_list()
    _, entries = parse_list(stdout)
    check(len(entries) == 1 and entries[0]["name"] == "proc-two", "exact survivor listed")

    code, stdout, _ = run(options.tool, ["recover"] + base + [journals])
    check(code == 0 and "No accepted snapshot operation" in stdout, "clean recover is a no-op")

    image_hash = sha256(image)
    journal_files = sorted(os.listdir(journals))
    journal_hashes = {name: sha256(os.path.join(journals, name)) for name in journal_files}

    code, _, _ = run(options.tool, ["list", image, "f" * 32, volume_uuid, "101", journals])
    check(code != 0, "wrong container refused")

    code, _, _ = run(options.tool, ["create"] + base + ["1", "stale-xid", "1", "0", journals])
    check(code != 0, "stale checkpoint refused")

    substituted = os.path.join(root, "substitute-journals")
    os.makedirs(substituted, exist_ok=True)
    code, _, stderr = run(options.tool, ["create"] + base +
                           [str(parse_list(snap_list()[1])[0]["xid"])] +
                           ["substituted", "2", "0", substituted])
    check(code != 0 and "SnapshotMaintenanceJournalNoChain" in stderr,
          "substituted clean journal refused: " + stderr[-300:])
    check(sha256(image) == image_hash, "image bytes unchanged by refusals")
    check({name: sha256(os.path.join(journals, name)) for name in journal_files} == journal_hashes,
          "real journals unchanged by refusals")

    # The held image refuses every other opener, including a reader: capture
    # the XID before holding.
    held_xid = str(parse_list(snap_list()[1])[0]["xid"])
    kernel32, held = hold_exclusive(image)
    try:
        code, _, stderr = run(options.tool, ["create"] + base +
                               [held_xid] +
                               ["while-held", "3", "0", journals])
        check(code != 0 and "ImageOwnerActive" in stderr,
              "active image owner refused: " + stderr[-300:])
    finally:
        kernel32.CloseHandle(held)
    check(sha256(image) == image_hash, "image bytes unchanged by active-owner refusal")

    print("SnapshotOwnerBridgeProcesses: %d checks, 0 failures" % CHECKS[0])


if __name__ == "__main__":
    try:
        main()
    except Exception as failure:
        print("FAIL: %s" % failure)
        sys.exit(1)
