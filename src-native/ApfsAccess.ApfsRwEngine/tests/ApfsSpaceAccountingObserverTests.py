"""Exercise the actual observer's opt-in snapshot payload query on private images."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import uuid


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--observer", type=Path, required=True)
    parser.add_argument("--fixture-builder", type=Path, required=True)
    args = parser.parse_args()
    root = args.root / ("observer-" + uuid.uuid4().hex[:12])
    root.mkdir(parents=True)
    cases = []

    def run(label, command, expected):
        result = subprocess.run(
            [str(item) for item in command], capture_output=True, text=True,
            encoding="utf-8", timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        (root / (label + ".stdout.txt")).write_text(result.stdout, encoding="utf-8")
        (root / (label + ".stderr.txt")).write_text(result.stderr, encoding="utf-8")
        assert result.returncode == expected, (label, result.returncode, result.stdout, result.stderr)
        cases.append({"case": label, "exitCode": result.returncode})
        return result

    run("fixtures", [args.fixture_builder, root / "images"], 0)
    images = root / "images"
    before = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in images.iterdir()}
    fields = ("snapshotPayloadReferenced", "snapshotPayloadSharedWithLive", "snapshotPayloadAbsentFromLive")

    def query(name):
        image = images / name
        return [args.observer, "--image", image, "--mode", "snapshot-space",
                "--container-uuid", "a" * 32, "--volume-uuid", "b" * 32,
                "--volume-oid", "101", "--checkpoint-xid", "20",
                "--store-offset-bytes", "0", "--store-size-bytes", str(image.stat().st_size)]

    def schema(document, name, observed):
        assert document["format"] == "apfs-access-snapshot-payload-space"
        assert document["version"] == 1 and document["readOnly"] is True
        assert document["accountingScope"] == "snapshot-payload-only"
        assert document["status"] == ("observed" if observed else "unknown")
        assert document["source"]["kind"] == "image"
        assert document["source"]["identity"].startswith("windows-file:")
        assert Path(document["source"]["path"]) == images / name
        assert document["requested"] == {
            "containerUuid": "a" * 32, "volumeUuid": "b" * 32, "volumeOid": "101",
            "checkpointXid": "20", "storeOffsetBytes": "0",
            "storeSizeBytes": str((images / name).stat().st_size),
        }
        assert all(document[key] is None for key in ("snapshot", "purgeable", "reclaimable"))

    for name, unit, expected, snapshots in (
        ("shared.img", 4096, (4, 4, 0), "1"),
        ("partial.img", 16384, (4, 2, 2), "1"),
        ("empty.img", 4096, (0, 0, 0), "0"),
    ):
        document = json.loads(run("positive-" + name, query(name), 0).stdout)
        schema(document, name, True)
        assert document["snapshotCount"] == snapshots
        assert document["allocationUnitBytes"] == unit and document["reason"] is None
        for key, blocks in zip(fields, expected):
            assert document[key] == {"blocks": str(blocks), "bytes": str(blocks * unit)}

    for name in ("multiple.img", "backup.img", "bad-reference.img"):
        document = json.loads(run("unknown-" + name, query(name), 3).stdout)
        schema(document, name, False)
        assert all(document[key] is None for key in fields + ("snapshotCount", "allocationUnitBytes"))
        assert isinstance(document["reason"], str) and document["reason"]
        if name == "multiple.img":
            assert document["reason"] == "SnapshotSpaceMultipleVolumesUnsupported"

    # This graph fails the opt-in census above but must remain a normal catalog
    # inventory. It catches accidental placement of the census on collect polls.
    collected = json.loads(run("default-collect", [args.observer, "--image", images / "bad-reference.img",
        "--profile", "snapshot-space-default-path", "--mode", "collect"], 0).stdout)
    assert collected["format"] == "apfs-access-raw-evidence" and collected["mode"] == "collect"
    assert not any(key in json.dumps(collected) for key in fields)
    volume = collected["topology"]["containers"][0]["sharedSpace"]["volumes"][0]
    assert volume["snapshot"] is None and volume["purgeable"] is None

    output = root / "published.json"
    published = run("published", query("shared.img") + ["--out", output], 0)
    assert not published.stdout.strip()
    schema(json.loads(output.read_text(encoding="utf-8")), "shared.img", True)
    saved = output.read_bytes()
    run("no-overwrite", query("shared.img") + ["--out", output], 2)
    assert output.read_bytes() == saved

    stale = query("shared.img")
    stale[stale.index("--checkpoint-xid") + 1] = "21"
    missing = json.loads(run("unavailable-checkpoint", stale, 3).stdout)
    assert missing["status"] == "unknown" and all(missing[key] is None for key in fields)
    for label, extra in (
        ("duplicate", ["--volume-oid", "101"]),
        ("broader-request", ["--require-whole-volume"]),
        ("profile-selector", ["--profile", "unexpected"]),
    ):
        rejected = run(label, query("shared.img") + extra, 2)
        assert not rejected.stdout.strip()
    device = query("shared.img")
    device[device.index("--image")] = "--device"
    device[2] = "not-a-device"
    assert not run("device-refused-before-open", device, 2).stdout.strip()

    after = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in images.iterdir()}
    assert before == after, "observer modified an image"
    receipt = {"cases": cases, "imageSha256": after, "passed": len(cases),
               "observer": str(args.observer),
               "observerSha256": hashlib.sha256(args.observer.read_bytes()).hexdigest()}
    (root / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(cases)} observer process cases; unchanged image hashes")
    print(f"EVIDENCE_ROOT={root}")


if __name__ == "__main__":
    main()
