#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
umask 077

readonly PROFILES=(
    single-volume multi-volume case-sensitive case-insensitive unicode
    incompatible-names links acl-xattrs resource-forks compression sparse-files
    clones snapshots volume-groups password-encryption backup-role corruption fusion
)

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
schema_path="$repo_root/tests/fixtures/apfs/manifest.schema.json"
test_mode=0
test_command_log=''
test_fail_profile=''
test_fail_immutable_window=0
test_publish_race=0
test_platform_name=''
current_profile=''
stage_root=''
destination_abs=''
destination_lock=''
published=0
attached_devices=()
immutable_paths=()

die() {
    printf 'error: %s\n' "$*" >&2
    exit 1
}

usage() {
    cat <<'EOF'
Usage:
  create_apfs_compatibility_fixtures.sh --validate-manifest FILE|-
  create_apfs_compatibility_fixtures.sh --self-test
  create_apfs_compatibility_fixtures.sh --destination PATH [options]

Generation options:
  --profile NAME              One Task 0 profile, or all (default: all)
  --credential-reference REF  External keychain: reference for password encryption
  --fusion-store-a PATH       Detached, read-only complete Fusion store image
  --fusion-store-b PATH       Detached, read-only complete Fusion store image

C0a boundary:
  Recipes and contracts can be exercised with --self-test. Production fixture
  publication remains fail-closed until the repo-owned native observer lands in
  Task 1. Caller-selected observer executables are never accepted.
EOF
}

validate_manifest() {
    local input="$1"
    local artifact_root="${2:-}"
    local temporary=''
    if [[ "$input" == '-' ]]; then
        temporary="$(mktemp "${TMPDIR:-/tmp}/apfs-manifest.XXXXXXXX.json")"
        command cat >"$temporary"
        input="$temporary"
    fi

    local status=0
    python3 - "$schema_path" "$input" "$artifact_root" <<'PY' || status=$?
import hashlib
import json
import os
import pathlib
import re
import stat
import sys


class Invalid(Exception):
    pass


def fail(message):
    raise Invalid(message)


def require(condition, message):
    if not condition:
        fail(message)


def streamed_sha256(path, expected_size):
    before = os.lstat(path)
    require(stat.S_ISREG(before.st_mode), f"artifact is not a regular file: {path}")
    require(before.st_size == expected_size, f"artifact size mismatch: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require(stat.S_ISREG(opened.st_mode), f"artifact is not a regular file: {path}")
        require((opened.st_dev, opened.st_ino, opened.st_size) ==
                (before.st_dev, before.st_ino, before.st_size),
                f"artifact changed while opening: {path}")
        digest = hashlib.sha256()
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            while True:
                chunk = handle.read(1024 * 1024)
                if not chunk:
                    break
                digest.update(chunk)
        after = os.fstat(descriptor)
        require((after.st_dev, after.st_ino, after.st_size) ==
                (opened.st_dev, opened.st_ino, opened.st_size),
                f"artifact changed while hashing: {path}")
        return before, digest.hexdigest()
    finally:
        os.close(descriptor)


def scan_secrets(value, path="$", key=None):
    forbidden = {
        "password", "passphrase", "secret", "token", "recoverykey",
        "recoverymaterial", "privatekey", "credentialvalue"
    }
    if key is not None and re.sub(r"[^a-z0-9]", "", key.lower()) in forbidden:
        fail(f"secret-like property is forbidden at {path}")
    if isinstance(value, dict):
        for child_key, child in value.items():
            scan_secrets(child, f"{path}.{child_key}", child_key)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            scan_secrets(child, f"{path}[{index}]")
    elif isinstance(value, str) and key != "externalReference":
        if re.search(r"(?i)(password|passphrase|recovery[-_ ]?key)\s*[:=]\s*\S+", value):
            fail(f"secret-like value is forbidden at {path}")
        if re.search(r"(?i)bearer\s+[A-Za-z0-9._~-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----", value):
            fail(f"secret-like value is forbidden at {path}")


def resolve_ref(root, reference):
    require(reference.startswith("#/"), f"schema: unsupported reference {reference}")
    node = root
    for part in reference[2:].split("/"):
        node = node[part.replace("~1", "/").replace("~0", "~")]
    return node


def type_matches(value, expected):
    return {
        "object": isinstance(value, dict),
        "array": isinstance(value, list),
        "string": isinstance(value, str),
        "integer": isinstance(value, int) and not isinstance(value, bool),
        "number": isinstance(value, (int, float)) and not isinstance(value, bool),
        "boolean": isinstance(value, bool),
        "null": value is None,
    }.get(expected, False)


def schema_validate(root, schema, value, path="$"):
    if "$ref" in schema:
        schema_validate(root, resolve_ref(root, schema["$ref"]), value, path)
        return

    expected = schema.get("type")
    if expected is not None:
        choices = expected if isinstance(expected, list) else [expected]
        require(any(type_matches(value, item) for item in choices),
                f"schema: {path} must have type {' or '.join(choices)}")
    if "const" in schema:
        require(value == schema["const"], f"schema: {path} must equal {schema['const']!r}")
    if "enum" in schema:
        require(value in schema["enum"], f"schema: {path} is not an allowed value")

    if isinstance(value, str):
        if "minLength" in schema:
            require(len(value) >= schema["minLength"], f"schema: {path} is too short")
        if "pattern" in schema:
            require(re.search(schema["pattern"], value) is not None,
                    f"schema: {path} does not match its path or value pattern")
    if isinstance(value, (int, float)) and not isinstance(value, bool) and "minimum" in schema:
        require(value >= schema["minimum"], f"schema: {path} is below its minimum")
    if isinstance(value, list):
        if "minItems" in schema:
            if path == "$.fusion.memberStoreIds" and len(value) < schema["minItems"]:
                fail("schema: Fusion requires exactly two observed member stores")
            require(len(value) >= schema["minItems"], f"schema: {path} has too few items")
        if "maxItems" in schema:
            require(len(value) <= schema["maxItems"], f"schema: {path} has too many items")
        if schema.get("uniqueItems"):
            encoded = [json.dumps(item, sort_keys=True, separators=(",", ":")) for item in value]
            require(len(encoded) == len(set(encoded)), f"schema: {path} contains duplicate items")
        if "items" in schema:
            for index, item in enumerate(value):
                schema_validate(root, schema["items"], item, f"{path}[{index}]")
    if isinstance(value, dict):
        required = schema.get("required", [])
        for name in required:
            require(name in value, f"schema: {path} missing required property {name}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(value) - set(properties))
            require(not extras, f"schema: {path} has unsupported properties: {', '.join(extras)}")
        for name, child_schema in properties.items():
            if name in value:
                schema_validate(root, child_schema, value[name], f"{path}.{name}")


def audit_schema(schema, path="#"):
    supported = {
        "$schema", "$id", "$defs", "$ref", "title", "type", "const", "enum",
        "pattern", "minLength", "minimum", "minItems", "maxItems", "uniqueItems",
        "required", "properties", "additionalProperties", "items"
    }
    extra = sorted(set(schema) - supported)
    require(not extra, f"schema: unsupported keywords at {path}: {', '.join(extra)}")
    for name, child in schema.get("$defs", {}).items():
        audit_schema(child, f"{path}/$defs/{name}")
    for name, child in schema.get("properties", {}).items():
        audit_schema(child, f"{path}/properties/{name}")
    if isinstance(schema.get("items"), dict):
        audit_schema(schema["items"], f"{path}/items")


def index_records(records, label, all_ids, require_uuid=False):
    result = {}
    uuids = set()
    for record in records:
        record_id = record["id"]
        require(record_id not in all_ids, f"duplicate stable identity: {record_id}")
        all_ids.add(record_id)
        result[record_id] = record
        if require_uuid:
            uuid = record["uuid"].lower()
            require(uuid not in uuids, f"duplicate {label} uuid: {uuid}")
            uuids.add(uuid)
    return result


def load_evidence_record(path, expected):
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        require((opened.st_dev, opened.st_ino, opened.st_size) ==
                (expected.st_dev, expected.st_ino, expected.st_size),
                "observation evidence file changed while opening")
        require(opened.st_size <= 1024 * 1024, "observation evidence file is too large to bind")
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            raw = handle.read(1024 * 1024 + 1)
        require(len(raw) <= 1024 * 1024, "observation evidence file is too large to bind")
        record = json.loads(raw.decode("utf-8"))
        require(isinstance(record, dict), "observation evidence file is not a JSON object")
        return record
    finally:
        os.close(descriptor)


def semantic_validate(data, artifact_root):
    all_ids = set()
    artifacts = index_records(data["artifacts"], "artifact", all_ids)
    topology = data["topology"]
    disks = index_records(topology["disks"], "disk", all_ids, True)
    partitions = index_records(topology["partitions"], "partition", all_ids, True)
    stores = index_records(topology["stores"], "store", all_ids, True)
    containers = index_records(topology["containers"], "container", all_ids, True)
    volumes = index_records(topology["volumes"], "volume", all_ids, True)
    groups = index_records(topology["groups"], "group", all_ids, True)

    observation = data["observation"]
    observation_artifact = artifacts.get(observation["evidenceArtifactId"])
    require(observation_artifact is not None and observation_artifact["kind"] == "observer-output",
            "observation evidence must reference an observer-output artifact")
    require(observation["recordSha256"] == observation_artifact["sha256"],
            "observation hash does not match its evidence artifact")
    expected_mode = "fusion" if data["profile"] == "fusion" else "collect"
    require(observation["mode"] == expected_mode, "observation mode does not match the profile")
    authority = observation["evidenceArtifactId"]

    for collection in (disks, partitions, stores, containers, volumes, groups):
        for record in collection.values():
            require(record["evidenceArtifactId"] == authority,
                    "identity and APFS feature facts require the single observation evidence artifact")
    for partition in partitions.values():
        require(partition["diskId"] in disks, "partition references an unknown disk")
    for store in stores.values():
        require(store["partitionId"] in partitions, "store references an unknown partition")
        require(store["containerId"] in containers, "store references an unknown container")
        artifact = artifacts.get(store["artifactId"])
        require(artifact is not None and artifact["storeId"] == store["id"],
                "store artifact binding is incomplete")
    for container in containers.values():
        actual_stores = {item["id"] for item in stores.values() if item["containerId"] == container["id"]}
        actual_volumes = {item["id"] for item in volumes.values() if item["containerId"] == container["id"]}
        require(set(container["storeIds"]) == actual_stores, "container store membership is incomplete")
        require(set(container["volumeIds"]) == actual_volumes, "container volume membership is incomplete")
    for volume in volumes.values():
        require(volume["containerId"] in containers, "volume references an unknown container")
        require(volume["groupId"] is None or volume["groupId"] in groups,
                "volume references an unknown group")
    for group in groups.values():
        require(len(group["volumeIds"]) >= 2, "volume group requires at least two observed members")
        require(all(item in volumes for item in group["volumeIds"]), "volume group references an unknown volume")
        require(all(volumes[item]["groupId"] == group["id"] for item in group["volumeIds"]),
                "volume group membership is incomplete")

    policies = {}
    for policy in data["mountPolicies"]:
        volume_id = policy["volumeId"]
        require(volume_id in volumes and volume_id not in policies, "mount policy volume binding is invalid")
        policies[volume_id] = policy
    require(set(policies) == set(volumes), "every volume requires exactly one mount policy")
    for volume_id, volume in volumes.items():
        policy = policies[volume_id]
        unsupported = volume["locked"] or volume["unknownFeatureBits"] or volume["incompatibleFeatureBits"]
        special = any(role != "data" for role in volume["roles"])
        require(not (unsupported and (policy["autoMount"] or policy["decision"] == "read-write")),
                "unsupported volume cannot auto-mount or mount read-write")
        require(not (special and policy["autoMount"]), "special-role volume cannot auto-mount")

    credentials = {}
    for credential in data["credentials"]:
        volume_id = credential["volumeId"]
        require(volume_id in volumes and volume_id not in credentials, "credential binding is invalid")
        credentials[volume_id] = credential
    for volume_id, volume in volumes.items():
        needs_reference = volume["encryptionMode"] != "none"
        require((volume_id in credentials) == needs_reference,
                "encrypted volume credential reference is missing or ambiguous")

    content = data["content"]
    files = index_records(content["files"], "file", all_ids)
    metadata = index_records(content["metadata"], "metadata", all_ids)
    acls = index_records(content["acls"], "acl", all_ids)
    xattrs = index_records(content["xattrs"], "xattr", all_ids)
    resource_forks = index_records(content["resourceForks"], "resource fork", all_ids)
    compression = index_records(content["compression"], "compression", all_ids)
    extents = index_records(content["extents"], "extent", all_ids)
    links = index_records(content["links"], "link", all_ids)
    clones = index_records(content["clones"], "clone", all_ids)
    snapshots = index_records(content["snapshots"], "snapshot", all_ids)

    for item in files.values():
        require(item["volumeId"] in volumes, "file references an unknown volume")
        require(item["metadataId"] in metadata, "file metadata reference is dangling")
        require(all(value in xattrs for value in item["xattrIds"]), "file xattr reference is dangling")
        require(all(value in extents for value in item["extentIds"]), "file extent reference is dangling")
        require(all(value in links for value in item["linkIds"]), "file link reference is dangling")
        require(item["cloneId"] is None or item["cloneId"] in clones, "file clone reference is dangling")
    for collection in (metadata, acls, xattrs, resource_forks, compression):
        for item in collection.values():
            require(item["fileId"] in files, "content evidence references an unknown file")
            require(item["evidenceArtifactId"] == authority,
                    "content metadata requires the single observation evidence artifact")
    for extent in extents.values():
        require(all(file_id in files for file_id in extent["fileIds"]),
                "extent references an unknown file")
        require(extent["evidenceArtifactId"] == authority,
                "extent requires the single observation evidence artifact")
        if extent["kind"] == "hole":
            require(extent["physicalOffset"] is None, "hole extent cannot claim a physical offset")
    for link in links.values():
        require(link["sourceFileId"] in files, "link source file is missing")
        require(link["targetFileId"] is None or link["targetFileId"] in files, "link target file is missing")
        require(link["evidenceArtifactId"] == authority, "link requires the single observation evidence artifact")
    for clone in clones.values():
        source = clone["sourceFileId"]
        target = clone["cloneFileId"]
        require(source in files and target in files and source != target, "clone file binding is invalid")
        require(clone["evidenceArtifactId"] == authority,
                "clone requires the single observation evidence artifact")
        for extent_id in clone["sharedExtentIds"]:
            extent = extents.get(extent_id)
            require(extent is not None, "clone shared extent reference is dangling")
            require({source, target}.issubset(set(extent["fileIds"])) and extent["refCount"] >= 2,
                    "shared extent must belong to source and clone with observed refcount")
    for snapshot in snapshots.values():
        require(snapshot["volumeId"] in volumes, "snapshot references an unknown volume")
        require(snapshot["evidenceArtifactId"] == authority,
                "snapshot requires the single observation evidence artifact")

    profile = data["profile"]
    required_feature = {
        "single-volume": "SingleVolume", "multi-volume": "MultiVolume",
        "case-sensitive": "CaseSensitive", "case-insensitive": "CaseInsensitive",
        "unicode": "Unicode", "incompatible-names": "IncompatibleNames",
        "links": "HardLinks", "acl-xattrs": "ExtendedAttributes",
        "resource-forks": "ResourceForks", "compression": "Compression",
        "sparse-files": "SparseFiles", "clones": "Clones", "snapshots": "Snapshots",
        "volume-groups": "VolumeGroups", "password-encryption": "PasswordEncryption",
        "backup-role": "BackupRole", "corruption": "Corruption", "fusion": "Fusion"
    }[profile]
    require(required_feature in data["features"], f"{profile} profile is missing observed feature {required_feature}")
    if profile == "single-volume":
        require(len(volumes) == 1, "single-volume profile requires one volume")
    if profile == "multi-volume":
        require(len(volumes) >= 2, "multi-volume profile requires at least two volumes")
    if profile == "case-sensitive":
        require(all(item["caseMode"] == "sensitive" for item in volumes.values()), "case mode was not observed")
    if profile == "case-insensitive":
        require(all(item["caseMode"] == "insensitive" for item in volumes.values()), "case mode was not observed")
    if profile == "unicode":
        require(any(not item["path"].isascii() for item in files.values()), "Unicode profile requires observed Unicode names")
    if profile == "incompatible-names":
        require(any(any(char in item["path"] for char in (":", "?")) or item["path"].endswith((".", " ")) for item in files.values()),
                "incompatible-names profile requires observed names")
    if profile == "links":
        require({item["kind"] for item in links.values()} == {"hard", "symbolic"}, "links profile requires both link kinds")
    if profile == "acl-xattrs":
        require(acls and xattrs, "acl-xattrs profile requires observed ACL and xattr evidence")
    if profile == "resource-forks":
        require(resource_forks, "resource-forks profile requires observer evidence")
    if profile == "compression":
        require(compression, "compression profile requires observer evidence")
    if profile == "sparse-files":
        require(any(item["kind"] == "hole" for item in extents.values()), "sparse profile requires observed hole extents")
    if profile == "clones":
        require(clones, "clones profile requires observed clone sharing")
    if profile == "snapshots":
        require(snapshots, "snapshots profile requires observed snapshots")
    if profile == "volume-groups":
        require(groups and any(len(item["volumeIds"]) == 2 for item in groups.values()),
                "volume-groups profile requires two observed members")
    if profile == "password-encryption":
        require(credentials and any(item["encryptionMode"] == "password" for item in volumes.values()),
                "password encryption requires observed encryption and an external reference")
    if profile == "backup-role":
        require(any("backup" in item["roles"] for item in volumes.values()), "backup role was not observed")

    corruption = data["corruption"]
    if profile == "corruption":
        require(corruption is not None, "corruption profile requires mutation evidence")
        source = artifacts.get(corruption["sourceArtifactId"])
        target = artifacts.get(corruption["targetArtifactId"])
        require(source is not None and target is not None and source is not target,
                "corruption source and target must be distinct artifacts")
        require(corruption["beforeSha256"] == source["sha256"] and corruption["afterSha256"] == target["sha256"],
                "corruption hashes do not bind source and target")
        require(source["sha256"] != target["sha256"], "corruption mutation did not change the target")
        require(corruption["sourceMode"] & 0o222 == 0, "corruption source mode is writable")
        require("uchg" in corruption["sourceFlags"], "corruption source is missing the immutable flag")
    else:
        require(corruption is None, "corruption evidence is only valid for the corruption profile")

    fusion = data["fusion"]
    if profile == "fusion":
        require(fusion is not None and len(fusion["memberStoreIds"]) == 2,
                "Fusion requires exactly two observed member stores")
        require(len(fusion["artifactIds"]) == 2, "Fusion requires exactly two sealed store artifacts")
        require(fusion["containerId"] in containers and containers[fusion["containerId"]]["fusion"],
                "Fusion container identity was not observed")
        require(set(fusion["memberStoreIds"]) == set(containers[fusion["containerId"]]["storeIds"]),
                "Fusion store identity is incomplete")
        bound_artifacts = [artifacts.get(item) for item in fusion["artifactIds"]]
        require(all(item is not None for item in bound_artifacts),
                "Fusion requires two sealed store artifacts")
        for artifact in bound_artifacts:
            require(artifact["kind"] == "raw-store",
                    "Fusion member must be a sealed raw-store artifact")
        require({item["path"] for item in bound_artifacts} ==
                {"images/fusion-store-a.img", "images/fusion-store-b.img"},
                "Fusion requires the exact sealed store artifact pair")
        require({item["storeId"] for item in bound_artifacts} == set(fusion["memberStoreIds"]),
                "Fusion artifact-to-store identity is incomplete")
        for store_id in fusion["memberStoreIds"]:
            require(store_id in stores, "Fusion member store is not an observed store")
            store_artifact_id = stores[store_id]["artifactId"]
            require(store_artifact_id in fusion["artifactIds"] and
                    artifacts[store_artifact_id]["storeId"] == store_id,
                    "Fusion store-to-artifact binding is incomplete")
    else:
        require(fusion is None, "Fusion evidence is only valid for the Fusion profile")

    payload = "".join(f"{item['id']}:{item['sha256']}\n" for item in sorted(artifacts.values(), key=lambda item: item["id"]))
    require(data["sha256"] == hashlib.sha256(payload.encode("ascii")).hexdigest(),
            "top-level sha256 does not match the artifact set")
    require(data["expectedManifest"] == f"manifests/{profile}.json",
            "expectedManifest does not match the profile")

    if artifact_root:
        root = pathlib.Path(artifact_root).resolve(strict=True)
        verified = {}
        for artifact in artifacts.values():
            candidate = root
            for part in pathlib.PurePosixPath(artifact["path"]).parts:
                candidate = candidate / part
                require(not candidate.is_symlink(), f"artifact path contains a symlink: {artifact['path']}")
            resolved = candidate.resolve(strict=True)
            require(os.path.commonpath((str(root), str(resolved))) == str(root),
                    f"artifact path escapes destination: {artifact['path']}")
            metadata, actual_hash = streamed_sha256(resolved, artifact["sizeBytes"])
            require(actual_hash == artifact["sha256"],
                    f"artifact hash mismatch: {artifact['path']}")
            require(metadata.st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH) == 0,
                    f"artifact is writable: {artifact['path']}")
            if data["corruption"] is not None and artifact["id"] == data["corruption"]["sourceArtifactId"]:
                source_stat = metadata
                if hasattr(stat, "UF_IMMUTABLE") and hasattr(source_stat, "st_flags"):
                    require(source_stat.st_flags & stat.UF_IMMUTABLE,
                            "corruption source lacks the macOS immutable flag")
            verified[artifact["id"]] = (resolved, metadata)

        evidence_resolved, evidence_stat = verified[observation["evidenceArtifactId"]]
        record = load_evidence_record(evidence_resolved, evidence_stat)
        require(record.get("format") == observation["format"],
                "observation evidence file format does not match the manifest envelope")
        require(record.get("version") == observation["version"],
                "observation evidence file version does not match the manifest envelope")
        require(record.get("observerId") == observation["observerId"],
                "observation evidence file observer does not match the manifest envelope")
        require(record.get("observerVersion") == observation["observerVersion"],
                "observation evidence file observer version does not match the manifest envelope")
        require(record.get("mode") == observation["mode"],
                "observation evidence file mode does not match the manifest envelope")
        require(record.get("profile") == data["profile"],
                "observation evidence file profile does not match the manifest")


try:
    with open(sys.argv[1], "r", encoding="utf-8") as handle:
        schema = json.load(handle)
    require(schema.get("$schema") == "https://json-schema.org/draft/2020-12/schema",
            "schema: manifest schema dialect is not pinned to Draft 2020-12")
    audit_schema(schema)
    with open(sys.argv[2], "r", encoding="utf-8") as handle:
        manifest = json.load(handle)
    scan_secrets(manifest)
    schema_validate(schema, schema, manifest)
    semantic_validate(manifest, sys.argv[3])
except (Invalid, KeyError, OSError, json.JSONDecodeError, TypeError, ValueError) as error:
    print(f"manifest invalid: {error}", file=sys.stderr)
    raise SystemExit(2)

print("manifest valid")
PY

    if [[ -n "$temporary" && -f "$temporary" ]]; then
        command rm -f "$temporary"
    fi
    return "$status"
}

log_command() {
    [[ "$test_mode" -eq 1 ]] || return 0
    printf '%s' "$1" >>"$test_command_log"
    shift
    local value
    for value in "$@"; do
        printf '\t%s' "$value" >>"$test_command_log"
    done
    printf '\n' >>"$test_command_log"
}

copy_file() {
    log_command cp "$@"
    command cp "$1" "$2"
}

move_path() {
    log_command mv "$@"
    command mv "$1" "$2"
}

atomic_move_no_replace() {
    log_command rename-noreplace "$@"
    python3 - "$1" "$2" <<'PY'
import ctypes
import os
import sys

source = os.fsencode(sys.argv[1])
destination = os.fsencode(sys.argv[2])

if sys.platform == "darwin":
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(-2, source, -2, destination, 0x00000004)  # AT_FDCWD, RENAME_EXCL
elif sys.platform.startswith("linux"):
    libc = ctypes.CDLL(None, use_errno=True)
    rename = libc.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(-100, source, -100, destination, 0x00000001)  # AT_FDCWD, RENAME_NOREPLACE
else:
    try:
        os.rename(os.fsdecode(source), os.fsdecode(destination))
    except OSError as error:
        print(f"atomic no-replace publication failed: {error}", file=sys.stderr)
        raise SystemExit(1)
    result = 0

if result != 0:
    error = ctypes.get_errno()
    print(f"atomic no-replace publication failed: {os.strerror(error)}", file=sys.stderr)
    raise SystemExit(1)
PY
}

remove_file() {
    log_command rm -f "$1"
    command rm -f "$1"
}

remove_tree() {
    local target="$1"
    [[ -n "$target" && -n "$stage_root" && "$target" == "$stage_root" ]] || die 'refusing unbounded cleanup'
    log_command rm -rf "$target"
    command rm -rf "$target"
}

assert_no_staging_leftovers() {
    local scope="$1"
    local prefix="$2"
    local failure="$3"
    local leftovers=0
    local candidate
    for candidate in "$scope"/."$prefix".task0.*; do
        if [[ -e "$candidate" || -L "$candidate" ]]; then
            leftovers=1
        fi
    done
    [[ "$leftovers" -eq 0 ]] || die "$failure"
}

require_regular_file_nofollow() {
    local path="$1"
    local expected_parent="${2:-}"
    python3 - "$path" "$expected_parent" <<'PY'
import os
import stat
import sys

path = os.path.abspath(sys.argv[1])
expected_parent = sys.argv[2]
parent_abs = os.path.abspath(expected_parent) if expected_parent else os.path.dirname(path)
if os.path.dirname(path) != parent_abs:
    raise SystemExit("owned output is outside its fixed staging directory")

# Reject symlinked parent components without following them.
parent = parent_abs
while True:
    try:
        component = os.lstat(parent)
    except OSError:
        raise SystemExit("owned output parent is not a fixed directory")
    if stat.S_ISLNK(component.st_mode):
        raise SystemExit("owned output parent contains a symlink")
    if not stat.S_ISDIR(component.st_mode):
        raise SystemExit("owned output parent is not a fixed directory")
    next_parent = os.path.dirname(parent)
    if next_parent == parent:
        break
    parent = next_parent

leaf_metadata = os.lstat(path)
if stat.S_ISLNK(leaf_metadata.st_mode) or not stat.S_ISREG(leaf_metadata.st_mode):
    raise SystemExit("owned output is not a regular no-follow file")

leaf = os.path.basename(path)
read_flags = os.O_RDONLY
if hasattr(os, "O_BINARY"):
    read_flags |= os.O_BINARY
if hasattr(os, "O_NOFOLLOW"):
    read_flags |= os.O_NOFOLLOW
dir_flags = os.O_RDONLY
if hasattr(os, "O_DIRECTORY"):
    dir_flags |= os.O_DIRECTORY
if hasattr(os, "O_NOFOLLOW"):
    dir_flags |= os.O_NOFOLLOW

descriptor = None
directory = None
try:
    try:
        directory = os.open(parent_abs, dir_flags)
        descriptor = os.open(leaf, read_flags, dir_fd=directory)
    except (NotImplementedError, OSError):
        if directory is not None:
            os.close(directory)
            directory = None
        # openat-style access is unavailable: fall back to a no-follow open
        # of the component-checked path plus an identity re-check.
        try:
            descriptor = os.open(path, read_flags)
        except OSError:
            raise SystemExit("owned output is not a regular no-follow file")
    opened = os.fstat(descriptor)
    if not stat.S_ISREG(opened.st_mode):
        raise SystemExit("owned output is not a regular no-follow file")
    if (leaf_metadata.st_dev, leaf_metadata.st_ino) != (opened.st_dev, opened.st_ino):
        raise SystemExit("owned output changed while opening")
finally:
    if descriptor is not None:
        os.close(descriptor)
    if directory is not None:
        os.close(directory)
PY
}

readonly_file() {
    require_regular_file_nofollow "$1"
    command chmod a-w "$1"
    python3 - "$1" <<'PY'
import os
import stat
import sys
mode = os.lstat(sys.argv[1]).st_mode
if not stat.S_ISREG(mode):
    raise SystemExit(1)
if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
    raise SystemExit(1)
PY
}

require_readonly_file() {
    require_regular_file_nofollow "$1" || die "read-only input is not a regular file: $1"
    python3 - "$1" <<'PY'
import os
import stat
import sys
mode = os.lstat(sys.argv[1]).st_mode
if mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
    raise SystemExit(1)
PY
}

require_distinct_files() {
    python3 - "$1" "$2" <<'PY'
import os
import sys
first = os.stat(sys.argv[1])
second = os.stat(sys.argv[2])
if (first.st_dev, first.st_ino) == (second.st_dev, second.st_ino):
    raise SystemExit("Fusion store inputs are hard-link aliases of the same file")
PY
}

chflags_command() {
    log_command chflags "$@"
    if [[ "$test_mode" -eq 0 ]]; then
        command chflags "$@"
    fi
}

immutable_file() {
    readonly_file "$1"
    immutable_paths+=("$1")
    chflags_command uchg "$1"
    [[ "$test_fail_immutable_window" -eq 0 ]] || die 'injected immutable registration-window failure'
    if [[ "$test_mode" -eq 0 ]]; then
        python3 - "$1" <<'PY'
import os
import stat
import sys
if not hasattr(stat, "UF_IMMUTABLE") or not os.stat(sys.argv[1]).st_flags & stat.UF_IMMUTABLE:
    raise SystemExit(1)
PY
    fi
}

sha256_file() {
    python3 - "$1" <<'PY'
import hashlib
import os
import sys
flags = os.O_RDONLY
if hasattr(os, "O_BINARY"):
    flags |= os.O_BINARY
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(sys.argv[1], flags)
digest = hashlib.sha256()
try:
    with os.fdopen(descriptor, "rb", closefd=False) as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
finally:
    os.close(descriptor)
print(digest.hexdigest())
PY
}

hdiutil_command() {
    log_command hdiutil "$@"
    if [[ "$test_mode" -eq 0 ]]; then
        command hdiutil "$@"
        return
    fi
    case "$1" in
        create)
            local output="${!#}"
            command dd if=/dev/zero of="$output" bs=4096 count=2 >/dev/null 2>&1
            ;;
        attach)
            local mount="$test_self_root/mount/$current_profile"
            local disk='disk99'
            [[ "${!#}" != *'fusion-store-a.img' ]] || disk='disk98'
            command mkdir -p "$mount"
            cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>system-entities</key><array>
<dict><key>dev-entry</key><string>/dev/$disk</string></dict>
<dict><key>dev-entry</key><string>/dev/${disk}s1</string><key>mount-point</key><string>$mount</string></dict>
</array></dict></plist>
EOF
            ;;
        detach) ;;
        *) die "fake hdiutil received unsupported command: $1" ;;
    esac
}

diskutil_command() {
    log_command diskutil "$@"
    if [[ "$test_mode" -eq 0 ]]; then
        command diskutil "$@"
        return
    fi
    if [[ "$1" == 'info' && "$2" == '-plist' ]]; then
        cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>DeviceIdentifier</key><string>disk99s1</string><key>TotalSize</key><integer>8192</integer></dict></plist>
EOF
    elif [[ "$1" == 'apfs' && "$2" == 'list' ]]; then
        cat <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict><key>Containers</key><array><dict><key>ContainerReference</key><string>disk99</string></dict></array></dict></plist>
EOF
    elif [[ "$1" == 'apfs' && "$2" == 'addVolume' ]]; then
        if [[ "$*" == *'APFSAccess-system'* ]]; then
            printf 'Created new APFS Volume disk99s2\n'
        else
            printf 'Created new APFS Volume disk99s3\n'
        fi
    elif [[ "$1" == 'apfs' && "$2" == 'listVolumeGroups' ]]; then
        printf '<plist version="1.0"><dict><key>groups</key><array/></dict></plist>\n'
    elif [[ "$1" == 'apfs' && "$2" == 'listSnapshots' ]]; then
        printf '<plist version="1.0"><dict><key>Snapshots</key><array/></dict></plist>\n'
    elif [[ "$1" == 'apfs' && "$2" == 'snapshot' ]]; then
        :
    elif [[ "$1" == 'apfs' && "$2" == 'changeVolumeRole' ]]; then
        :
    else
        die "fake diskutil received unsupported command: $*"
    fi
}

plutil_command() {
    log_command plutil "$@"
    if [[ "$test_mode" -eq 0 ]]; then
        command plutil "$@"
    fi
}

security_password() {
    log_command security find-generic-password -w -s "$1"
    if [[ "$test_mode" -eq 0 ]]; then
        command security find-generic-password -w -s "$1"
    else
        printf 'self-test-password'
    fi
}

detach_all() {
    local device
    for device in "${attached_devices[@]}"; do
        hdiutil_command detach "$device" >/dev/null 2>&1 || hdiutil_command detach "$device" -force >/dev/null 2>&1 || true
    done
    attached_devices=()
}

cleanup() {
    detach_all
    if [[ "$published" -eq 0 && -n "$stage_root" && -d "$stage_root" ]]; then
        local immutable
        for immutable in "${immutable_paths[@]}"; do
            if [[ "$immutable" == "$stage_root"/* && -f "$immutable" ]]; then
                chflags_command nouchg "$immutable" || true
                command chmod u+w "$immutable" || true
            fi
        done
        remove_tree "$stage_root"
    fi
    if [[ -n "$destination_lock" && -d "$destination_lock" ]]; then
        command rmdir "$destination_lock" 2>/dev/null || true
    fi
}

parse_attach_plist() {
    python3 - "$1" <<'PY'
import plistlib
import sys
with open(sys.argv[1], "rb") as handle:
    data = plistlib.load(handle)
matches = []
for entity in data.get("system-entities", []):
    if entity.get("dev-entry") and entity.get("mount-point"):
        matches.append((entity["dev-entry"], entity["mount-point"]))
if len(matches) != 1:
    raise SystemExit("attach plist did not identify exactly one mounted volume")
print(matches[0][0] + "\t" + matches[0][1])
PY
}

parse_store_attach_plist() {
    python3 - "$1" <<'PY'
import plistlib
import sys
with open(sys.argv[1], "rb") as handle:
    data = plistlib.load(handle)
devices = [item.get("dev-entry") for item in data.get("system-entities", []) if item.get("dev-entry")]
if not devices:
    raise SystemExit("attach plist did not identify a store device")
print(devices[-1])
PY
}

create_volume_group() {
    local container="$1"
    local evidence="$2"
    local output
    output="$(diskutil_command apfs addVolume "$container" APFSX APFSAccess-system -role S)"
    local system_device
    system_device="$(printf '%s\n' "$output" | python3 -c 'import re,sys; m=re.findall(r"(?:/dev/)?(disk[0-9]+s[0-9]+)", sys.stdin.read()); print("/dev/" + m[-1] if len(m) == 1 else "")')"
    [[ "$system_device" == /dev/disk*s* ]] || die 'system volume identity is ambiguous'
    diskutil_command apfs addVolume "$container" APFSX APFSAccess-data -role D -groupWith "$system_device" >/dev/null
    diskutil_command apfs listVolumeGroups -plist >"$evidence"
}

apply_recipe() {
    local profile="$1"
    local mount_root="$2"
    local device="$3"
    local evidence="$4"
    local container="${device%s*}"
    : >"$evidence"
    case "$profile" in
        single-volume|case-sensitive|case-insensitive|password-encryption|corruption)
            diskutil_command info -plist "$device" >"$evidence"
            ;;
        multi-volume)
            diskutil_command apfs addVolume "$container" APFS APFSAccess-secondary >"$evidence"
            ;;
        unicode)
            python3 - "$mount_root" <<'PY'
import pathlib
import sys
for name in ("cafe\u0301.txt", "caf\u00e9.txt", "\u4e2d\u6587.txt"):
    pathlib.Path(sys.argv[1], name).write_text(name, encoding="utf-8")
PY
            command find "$mount_root" -print >"$evidence"
            ;;
        incompatible-names)
            if [[ "$test_mode" -eq 0 ]]; then
                python3 - "$mount_root" <<'PY'
import pathlib
import sys
for name in ("CON", "trailing-dot.", "trailing-space ", "colon:name", "question?mark"):
    pathlib.Path(sys.argv[1], name).write_text("name-vector", encoding="ascii")
PY
                command find "$mount_root" -print >"$evidence"
            else
                printf 'captured incompatible names\n' >"$evidence"
            fi
            ;;
        links)
            command ln "$mount_root/readme.txt" "$mount_root/hard-link.txt"
            command ln -s readme.txt "$mount_root/symbolic-link"
            command find "$mount_root" -print >"$evidence"
            ;;
        acl-xattrs)
            if [[ "$test_mode" -eq 0 ]]; then
                command xattr -w com.apfsaccess.fixture xattr-v1 "$mount_root/readme.txt"
                command chmod +a 'group:everyone allow read' "$mount_root/readme.txt"
                command ls -lde@ "$mount_root/readme.txt" >"$evidence"
            else
                printf 'captured ACL and xattr\n' >"$evidence"
            fi
            ;;
        resource-forks)
            if [[ "$test_mode" -eq 0 ]]; then
                printf 'resource-fork-v1\n' >"$mount_root/readme.txt/..namedfork/rsrc"
                command xattr -l "$mount_root/readme.txt" >"$evidence"
            else
                printf 'captured resource fork\n' >"$evidence"
            fi
            ;;
        compression)
            if [[ "$test_mode" -eq 0 ]]; then
                command dd if=/dev/zero of="$mount_root/compression-source.bin" bs=1m count=8 >/dev/null 2>&1
                command ditto --hfsCompression "$mount_root/compression-source.bin" "$mount_root/compressed.txt"
                command ls -lO "$mount_root/compressed.txt" >"$evidence"
            else
                printf 'compressed\n' >"$mount_root/compressed.txt"
                printf 'captured compression\n' >"$evidence"
            fi
            ;;
        sparse-files)
            if [[ "$test_mode" -eq 0 ]]; then
                command mkfile -n 64m "$mount_root/sparse.bin"
            else
                command dd if=/dev/zero of="$mount_root/sparse.bin" bs=1 count=1 seek=65535 >/dev/null 2>&1
            fi
            command ls -l "$mount_root/sparse.bin" >"$evidence"
            ;;
        clones)
            if [[ "$test_mode" -eq 0 ]]; then
                command cp -c "$mount_root/readme.txt" "$mount_root/clone.txt"
            else
                copy_file "$mount_root/readme.txt" "$mount_root/clone.txt"
            fi
            command ls -li "$mount_root/readme.txt" "$mount_root/clone.txt" >"$evidence"
            ;;
        snapshots)
            diskutil_command apfs snapshot "$device" -name apfsaccess-snapshot >/dev/null
            diskutil_command apfs listSnapshots "$device" -plist >"$evidence"
            ;;
        volume-groups)
            create_volume_group "$container" "$evidence"
            ;;
        backup-role)
            diskutil_command apfs changeVolumeRole "$device" B >/dev/null
            diskutil_command info -plist "$device" >"$evidence"
            ;;
        *) die "unsupported sparse profile: $profile" ;;
    esac
    [[ -s "$evidence" ]] || die "profile recipe emitted no evidence: $profile"
}

write_fake_manifest() {
    local profile="$1"
    local primary="$2"
    local secondary="$3"
    local observer_evidence="$4"
    local draft="$5"
    local credential="$6"
    python3 - "$profile" "$stage_root" "$primary" "$secondary" "$observer_evidence" "$draft" "$credential" <<'PY'
import hashlib
import json
import os
import pathlib
import stat
import sys

profile, root_arg, primary_arg, secondary_arg, evidence_arg, draft_arg, credential = sys.argv[1:]
root = pathlib.Path(root_arg)
primary = pathlib.Path(primary_arg)
secondary = pathlib.Path(secondary_arg) if secondary_arg else None
evidence = pathlib.Path(evidence_arg)
draft = pathlib.Path(draft_arg)
evidence.write_text(json.dumps({
    "format": "apfs-access-raw-evidence",
    "version": 1,
    "observerId": "apfs-access-owned-raw-observer",
    "observerVersion": "1.0.0",
    "mode": "fusion" if profile == "fusion" else "collect",
    "synthetic": True,
    "profile": profile,
}, sort_keys=True) + "\n", encoding="ascii")
evidence.chmod(0o444)


def sha(path):
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def uid(prefix, number):
    return f"{number:08d}-0000-4000-8000-{number:012d}"


artifacts = []


def artifact(item_id, path, kind, store_id=None):
    artifacts.append({
        "id": item_id,
        "path": path.relative_to(root).as_posix(),
        "kind": kind,
        "storage": "destination",
        "sha256": sha(path),
        "sizeBytes": path.stat().st_size,
        "readOnly": True,
        "storeId": store_id,
    })


if profile == "fusion":
    artifact("artifact:store-a", primary, "raw-store", "store:s1")
    artifact("artifact:store-b", secondary, "raw-store", "store:s2")
elif profile == "corruption":
    artifact("artifact:source", primary, "corruption-source", "store:s1")
    artifact("artifact:target", secondary, "corruption-target")
else:
    artifact("artifact:image", primary, "sparse-image", "store:s1")

for index, path in enumerate(sorted((root / "evidence").glob(f"{profile}-*.plist"))):
    artifact(f"artifact:diskutil-{index + 1}", path, "diskutil-output")
artifact("artifact:observer", evidence, "observer-output")

disk_count = 2 if profile == "fusion" else 1
disks = []
partitions = []
stores = []
for index in range(1, disk_count + 1):
    disks.append({"id": f"disk:d{index}", "deviceIdentifier": f"disk9{index}", "uuid": uid("disk", index), "sizeBytes": 8192, "evidenceArtifactId": "artifact:observer"})
    partitions.append({"id": f"partition:p{index}", "uuid": uid("partition", 10 + index), "diskId": f"disk:d{index}", "index": 1, "startByte": 4096, "sizeBytes": 4096, "evidenceArtifactId": "artifact:observer"})
    stores.append({"id": f"store:s{index}", "uuid": uid("store", 20 + index), "partitionId": f"partition:p{index}", "containerId": "container:c1", "artifactId": "artifact:store-" + ("a" if index == 1 else "b") if profile == "fusion" else ("artifact:source" if profile == "corruption" else "artifact:image"), "sizeBytes": 4096, "evidenceArtifactId": "artifact:observer"})

volume_count = 2 if profile in ("multi-volume", "volume-groups") else 1
volumes = []
groups = []
for index in range(1, volume_count + 1):
    roles = ["data"]
    group_id = None
    if profile == "volume-groups":
        roles = ["system"] if index == 1 else ["data"]
        group_id = "group:g1"
    elif profile == "backup-role":
        roles = ["backup"]
    volumes.append({
        "id": f"volume:v{index}", "uuid": uid("volume", 30 + index), "objectId": str(100 + index),
        "containerId": "container:c1", "name": f"APFSAccess-{profile}-{index}", "roles": roles,
        "groupId": group_id, "caseMode": "sensitive" if profile == "case-sensitive" else "insensitive",
        "encryptionMode": "password" if profile == "password-encryption" else "none", "locked": False,
        "compatibleFeatureBits": ["0x1"], "unknownFeatureBits": [], "incompatibleFeatureBits": [],
        "evidenceArtifactId": "artifact:observer"
    })
if profile == "volume-groups":
    groups.append({"id": "group:g1", "uuid": uid("group", 41), "volumeIds": ["volume:v1", "volume:v2"], "evidenceArtifactId": "artifact:observer"})

feature = {
    "single-volume": "SingleVolume", "multi-volume": "MultiVolume", "case-sensitive": "CaseSensitive",
    "case-insensitive": "CaseInsensitive", "unicode": "Unicode", "incompatible-names": "IncompatibleNames",
    "links": "HardLinks", "acl-xattrs": "ExtendedAttributes", "resource-forks": "ResourceForks",
    "compression": "Compression", "sparse-files": "SparseFiles", "clones": "Clones",
    "snapshots": "Snapshots", "volume-groups": "VolumeGroups", "password-encryption": "PasswordEncryption",
    "backup-role": "BackupRole", "corruption": "Corruption", "fusion": "Fusion"
}[profile]
features = [feature, "PosixMetadata"]
files = []
metadata = []
extents = []


def add_file(file_id, path, extent_kind="data"):
    metadata_id = f"metadata:{file_id}"
    extent_id = f"extent:{file_id}"
    digest = hashlib.sha256(path.encode("utf-8")).hexdigest()
    files.append({"id": f"file:{file_id}", "volumeId": "volume:v1", "path": path, "sha256": digest, "sizeBytes": len(path.encode("utf-8")), "metadataId": metadata_id, "xattrIds": [], "extentIds": [extent_id], "linkIds": [], "cloneId": None})
    metadata.append({"id": metadata_id, "fileId": f"file:{file_id}", "inode": len(metadata) + 42, "mode": 420, "uid": 501, "gid": 20, "nlink": 1, "logicalSizeBytes": len(path.encode("utf-8")), "allocatedSizeBytes": 4096, "flags": [], "evidenceArtifactId": "artifact:observer"})
    extents.append({"id": extent_id, "fileIds": [f"file:{file_id}"], "logicalOffset": 0, "lengthBytes": max(1, len(path.encode("utf-8"))), "physicalOffset": None if extent_kind == "hole" else 4096 * (len(extents) + 1), "kind": extent_kind, "refCount": 1, "evidenceArtifactId": "artifact:observer"})


add_file("readme", "readme.txt")
if profile == "unicode":
    add_file("unicode", "caf\u00e9.txt")
if profile == "incompatible-names":
    add_file("incompatible", "colon:name")
if profile == "sparse-files":
    add_file("sparse", "sparse.bin", "hole")

acls = []
xattrs = []
resource_forks = []
compression = []
links = []
clones = []
snapshots = []
if profile == "links":
    add_file("hardlink", "hard-link.txt")
    links.extend([
        {"id": "link:hard", "kind": "hard", "sourceFileId": "file:readme", "targetFileId": "file:hardlink", "targetPath": None, "evidenceArtifactId": "artifact:observer"},
        {"id": "link:symbolic", "kind": "symbolic", "sourceFileId": "file:readme", "targetFileId": None, "targetPath": "readme.txt", "evidenceArtifactId": "artifact:observer"}
    ])
    files[0]["linkIds"] = ["link:hard", "link:symbolic"]
if profile == "acl-xattrs":
    acls.append({"id": "acl:a1", "fileId": "file:readme", "entryCount": 1, "entriesSha256": "a" * 64, "evidenceArtifactId": "artifact:observer"})
    xattrs.append({"id": "xattr:x1", "fileId": "file:readme", "name": "com.apfsaccess.fixture", "sizeBytes": 8, "sha256": "b" * 64, "evidenceArtifactId": "artifact:observer"})
    files[0]["xattrIds"] = ["xattr:x1"]
if profile == "resource-forks":
    resource_forks.append({"id": "resource:r1", "fileId": "file:readme", "sizeBytes": 8, "sha256": "c" * 64, "evidenceArtifactId": "artifact:observer"})
if profile == "compression":
    compression.append({"id": "compression:c1", "fileId": "file:readme", "algorithm": "decmpfs", "logicalSizeBytes": 12, "allocatedSizeBytes": 8, "evidenceArtifactId": "artifact:observer"})
if profile == "clones":
    add_file("clone", "clone.txt")
    shared = extents[0]
    shared["fileIds"].append("file:clone")
    shared["refCount"] = 2
    files[-1]["extentIds"] = [shared["id"]]
    extents.pop()
    files[0]["cloneId"] = "clone:c1"
    files[-1]["cloneId"] = "clone:c1"
    clones.append({"id": "clone:c1", "sourceFileId": "file:readme", "cloneFileId": "file:clone", "sharedExtentIds": [shared["id"]], "evidenceArtifactId": "artifact:observer"})
if profile == "snapshots":
    snapshots.append({"id": "snapshot:s1", "volumeId": "volume:v1", "uuid": uid("snapshot", 51), "name": "apfsaccess-snapshot", "xid": "900", "evidenceArtifactId": "artifact:observer"})

policies = []
for volume in volumes:
    special = any(role != "data" for role in volume["roles"])
    policies.append({"volumeId": volume["id"], "requestedAccess": "read-write", "decision": "read-only" if special else "read-write", "autoMount": not special, "reasons": ["special-role"] if special else []})

credentials = []
if profile == "password-encryption":
    credentials.append({"volumeId": "volume:v1", "externalReference": credential})

corruption = None
if profile == "corruption":
    corruption = {"sourceArtifactId": "artifact:source", "targetArtifactId": "artifact:target", "mutationOffsetBytes": 4096, "beforeSha256": sha(primary), "afterSha256": sha(secondary), "sourceMode": stat.S_IMODE(primary.stat().st_mode), "sourceFlags": ["uchg"]}
fusion = None
if profile == "fusion":
    fusion = {"containerId": "container:c1", "memberStoreIds": ["store:s1", "store:s2"], "artifactIds": ["artifact:store-a", "artifact:store-b"]}

observer_hash = next(item["sha256"] for item in artifacts if item["id"] == "artifact:observer")
observation = {
    "format": "apfs-access-raw-evidence",
    "version": 1,
    "observerId": "apfs-access-owned-raw-observer",
    "observerVersion": "1.0.0",
    "mode": "fusion" if profile == "fusion" else "collect",
    "evidenceArtifactId": "artifact:observer",
    "recordSha256": observer_hash,
}

manifest = {
    "schemaVersion": 1, "fixtureId": profile, "profile": profile,
    "macOS": {"version": "15.6.1", "build": "24G90"}, "features": features,
    "topology": {
        "disks": disks, "partitions": partitions, "stores": stores,
        "containers": [{"id": "container:c1", "uuid": uid("container", 61), "blockSizeBytes": 4096, "storeIds": [item["id"] for item in stores], "volumeIds": [item["id"] for item in volumes], "fusion": profile == "fusion", "compatibleFeatureBits": ["0x1"], "unknownFeatureBits": [], "incompatibleFeatureBits": [], "evidenceArtifactId": "artifact:observer"}],
        "volumes": volumes, "groups": groups
    },
    "mountPolicies": policies, "credentials": credentials, "observation": observation,
    "content": {"files": files, "metadata": metadata, "acls": acls, "xattrs": xattrs, "resourceForks": resource_forks, "compression": compression, "extents": extents, "links": links, "clones": clones, "snapshots": snapshots},
    "artifacts": artifacts, "corruption": corruption, "fusion": fusion,
    "sha256": "", "expectedManifest": f"manifests/{profile}.json"
}
payload = "".join(f"{item['id']}:{item['sha256']}\n" for item in sorted(artifacts, key=lambda item: item["id"]))
manifest["sha256"] = hashlib.sha256(payload.encode("ascii")).hexdigest()
draft.write_text(json.dumps(manifest, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
}

invoke_observer() {
    local mode="$1"
    local profile="$2"
    local primary="$3"
    local secondary="$4"
    local observer_evidence="$5"
    local draft="$6"
    shift 6
    if [[ "$test_mode" -eq 1 ]]; then
        write_fake_manifest "$profile" "$primary" "$secondary" "$observer_evidence" "$draft" "$credential_reference"
        return
    fi
    die 'owned APFS observer is unavailable until Task 1'
}

finalize_profile() {
    local profile="$1"
    local primary="$2"
    local secondary="$3"
    local info="$4"
    local topology="$5"
    local observer_evidence="$stage_root/evidence/$profile-observer.json"
    local draft="$stage_root/manifests/$profile.draft.json"
    readonly_file "$primary"
    [[ -z "$secondary" ]] || readonly_file "$secondary"
    readonly_file "$info"
    readonly_file "$topology"
    local observer_args=(--diskutil-info "$info" --diskutil-apfs "$topology")
    if [[ "$profile" == 'password-encryption' ]]; then
        observer_args+=(--credential-reference "$credential_reference")
    fi
    invoke_observer collect "$profile" "$primary" "$secondary" "$observer_evidence" "$draft" "${observer_args[@]}"
    require_regular_file_nofollow "$observer_evidence" "$stage_root/evidence" || die "observer evidence is not an owned regular file for $profile"
    require_regular_file_nofollow "$draft" "$stage_root/manifests" || die "draft manifest is not an owned regular file for $profile"
    [[ -s "$observer_evidence" && -s "$draft" ]] || die "observer did not produce evidence and manifest for $profile"
    readonly_file "$observer_evidence"
    validate_manifest "$draft" "$stage_root" >/dev/null
    require_regular_file_nofollow "$draft" "$stage_root/manifests" || die "draft manifest changed before publication for $profile"
    move_path "$draft" "$stage_root/manifests/$profile.json"
    readonly_file "$stage_root/manifests/$profile.json"
}

generate_sparse_profile() {
    local profile="$1"
    current_profile="$profile"
    [[ "$test_fail_profile" != "$profile" ]] || die "injected failure for $profile"
    local image="$stage_root/images/$profile.sparseimage"
    local attach="$stage_root/evidence/$profile-attach.plist"
    local recipe="$stage_root/evidence/$profile-recipe.txt"
    local info="$stage_root/evidence/$profile-info.plist"
    local topology="$stage_root/evidence/$profile-apfs.plist"
    local filesystem='APFS'
    [[ "$profile" != 'case-sensitive' && "$profile" != 'unicode' && "$profile" != 'incompatible-names' && "$profile" != 'volume-groups' ]] || filesystem='APFSX'

    if [[ "$profile" == 'password-encryption' ]]; then
        local secret
        secret="$(security_password "${credential_reference#keychain:}")" || die 'credential lookup failed'
        printf '%s' "$secret" | hdiutil_command create -size 128m -type SPARSE -fs "$filesystem" -volname "APFSAccess-$profile" -encryption AES-256 -stdinpass "$image" >/dev/null
        unset secret
    else
        hdiutil_command create -size 128m -type SPARSE -fs "$filesystem" -volname "APFSAccess-$profile" "$image" >/dev/null
    fi
    if [[ "$profile" == 'password-encryption' ]]; then
        local attach_secret
        attach_secret="$(security_password "${credential_reference#keychain:}")" || die 'credential lookup failed for encrypted attach'
        printf '%s' "$attach_secret" | hdiutil_command attach -stdinpass -nobrowse -plist "$image" >"$attach"
        unset attach_secret
    else
        hdiutil_command attach -nobrowse -plist "$image" >"$attach"
    fi
    local identity
    identity="$(parse_attach_plist "$attach")" || die 'image attach identity is ambiguous'
    local device="${identity%%$'\t'*}"
    local mount_root="${identity#*$'\t'}"
    [[ -n "$device" && -d "$mount_root" ]] || die 'image attach did not produce a mounted APFS volume'
    attached_devices=("$device")
    printf 'apfs-access-fixture\n' >"$mount_root/readme.txt"
    apply_recipe "$profile" "$mount_root" "$device" "$recipe"
    diskutil_command info -plist "$device" >"$info"
    diskutil_command apfs list -plist "$device" >"$topology"
    plutil_command -lint "$info" >/dev/null
    plutil_command -lint "$topology" >/dev/null
    hdiutil_command detach "$device" >/dev/null
    attached_devices=()
    remove_file "$attach"

    local secondary=''
    if [[ "$profile" == 'corruption' ]]; then
        local source="$stage_root/images/corruption-source.sparseimage"
        local target="$stage_root/images/corruption-target.sparseimage"
        move_path "$image" "$source"
        copy_file "$source" "$target"
        immutable_file "$source"
        python3 - "$target" <<'PY'
import os
import sys
with open(sys.argv[1], "r+b", buffering=0) as handle:
    handle.seek(4096)
    before = handle.read(1)
    handle.seek(4096)
    handle.write(bytes([(before[0] if before else 0) ^ 0x01]))
    handle.flush()
    os.fsync(handle.fileno())
PY
        readonly_file "$target"
        image="$source"
        secondary="$target"
    fi
    finalize_profile "$profile" "$image" "$secondary" "$info" "$topology"
}

generate_fusion_profile() {
    current_profile='fusion'
    [[ "$test_fail_profile" != 'fusion' ]] || die 'injected failure for fusion'
    [[ -n "$fusion_store_a" && -n "$fusion_store_b" && "$fusion_store_a" != "$fusion_store_b" ]] || die 'Fusion generation requires two distinct store inputs'
    [[ -f "$fusion_store_a" && -f "$fusion_store_b" ]] || die 'Fusion store inputs must be complete regular image files'
    require_readonly_file "$fusion_store_a" || die 'Fusion store A must already be read-only'
    require_readonly_file "$fusion_store_b" || die 'Fusion store B must already be read-only'
    require_distinct_files "$fusion_store_a" "$fusion_store_b" || die 'Fusion store inputs are the same file'
    local before_a before_b
    before_a="$(sha256_file "$fusion_store_a")"
    before_b="$(sha256_file "$fusion_store_b")"
    local copy_a="$stage_root/images/fusion-store-a.img"
    local copy_b="$stage_root/images/fusion-store-b.img"
    copy_file "$fusion_store_a" "$copy_a"
    copy_file "$fusion_store_b" "$copy_b"
    [[ "$before_a" == "$(sha256_file "$fusion_store_a")" && "$before_b" == "$(sha256_file "$fusion_store_b")" ]] || die 'Fusion input changed during sealed copy'
    readonly_file "$copy_a"
    readonly_file "$copy_b"
    local sealed_a sealed_b
    sealed_a="$(sha256_file "$copy_a")"
    sealed_b="$(sha256_file "$copy_b")"

    local attach_a="$stage_root/evidence/fusion-store-a-attach.plist"
    local attach_b="$stage_root/evidence/fusion-store-b-attach.plist"
    hdiutil_command attach -readonly -nomount -plist "$copy_a" >"$attach_a"
    local device_a
    device_a="$(parse_store_attach_plist "$attach_a")" || die 'Fusion store A attach identity is ambiguous'
    attached_devices=("$device_a")
    hdiutil_command attach -readonly -nomount -plist "$copy_b" >"$attach_b"
    local device_b
    device_b="$(parse_store_attach_plist "$attach_b")" || die 'Fusion store B attach identity is ambiguous'
    [[ "$device_a" != "$device_b" ]] || die 'Fusion stores resolved to the same device identity'
    attached_devices=("$device_a" "$device_b")

    local info_a="$stage_root/evidence/fusion-store-a-info.plist"
    local info_b="$stage_root/evidence/fusion-store-b-info.plist"
    local topology_a="$stage_root/evidence/fusion-store-a-apfs.plist"
    local topology_b="$stage_root/evidence/fusion-store-b-apfs.plist"
    diskutil_command info -plist "$device_a" >"$info_a"
    diskutil_command info -plist "$device_b" >"$info_b"
    diskutil_command apfs list -plist "$device_a" >"$topology_a"
    diskutil_command apfs list -plist "$device_b" >"$topology_b"
    plutil_command -lint "$info_a" >/dev/null
    plutil_command -lint "$info_b" >/dev/null
    plutil_command -lint "$topology_a" >/dev/null
    plutil_command -lint "$topology_b" >/dev/null
    hdiutil_command detach "$device_a" >/dev/null
    hdiutil_command detach "$device_b" >/dev/null
    attached_devices=()
    remove_file "$attach_a"
    remove_file "$attach_b"
    [[ "$before_a" == "$(sha256_file "$copy_a")" && "$before_b" == "$(sha256_file "$copy_b")" ]] || die 'Fusion sealed copies changed during observation'
    readonly_file "$info_a"
    readonly_file "$info_b"
    readonly_file "$topology_a"
    readonly_file "$topology_b"
    local observer_evidence="$stage_root/evidence/fusion-observer.json"
    local draft="$stage_root/manifests/fusion.draft.json"
    invoke_observer fusion fusion "$copy_a" "$copy_b" "$observer_evidence" "$draft" \
        --device-a "$device_a" --device-b "$device_b" \
        --diskutil-info-a "$info_a" --diskutil-info-b "$info_b" \
        --diskutil-apfs-a "$topology_a" --diskutil-apfs-b "$topology_b"
    require_regular_file_nofollow "$observer_evidence" "$stage_root/evidence" || die 'Fusion observer evidence is not an owned regular file'
    require_regular_file_nofollow "$draft" "$stage_root/manifests" || die 'Fusion draft manifest is not an owned regular file'
    [[ "$sealed_a" == "$(sha256_file "$copy_a")" && "$sealed_b" == "$(sha256_file "$copy_b")" ]] || die 'Fusion sealed copies changed during observer execution'
    readonly_file "$observer_evidence"
    validate_manifest "$draft" "$stage_root" >/dev/null
    require_regular_file_nofollow "$draft" "$stage_root/manifests" || die 'Fusion draft manifest changed before publication'
    move_path "$draft" "$stage_root/manifests/fusion.json"
    readonly_file "$stage_root/manifests/fusion.json"
}

is_known_profile() {
    local profile
    for profile in "${PROFILES[@]}"; do
        [[ "$profile" == "$1" ]] && return 0
    done
    return 1
}

canonical_new_path() {
    local candidate="$1"
    local parent
    parent="$(cd "$(dirname "$candidate")" && pwd -P)" || die "destination parent does not exist: $candidate"
    printf '%s/%s\n' "$parent" "$(basename "$candidate")"
}

canonical_existing_file() {
    [[ -f "$1" ]] || die "file does not exist: $1"
    local parent
    parent="$(cd "$(dirname "$1")" && pwd -P)"
    printf '%s/%s\n' "$parent" "$(basename "$1")"
}

assert_outside_repository() {
    case "$1" in
        "$repo_root"|"$repo_root"/*) die 'private inputs and output must stay outside the repository' ;;
    esac
}

run_generation() {
    local parent base profile
    parent="$(dirname "$destination_abs")"
    base="$(basename "$destination_abs")"
    [[ ! -e "$destination_abs" && ! -L "$destination_abs" ]] || die 'destination must not already exist'
    stage_root="$(mktemp -d "$parent/.$base.task0.XXXXXXXX")"
    [[ "$stage_root" == "$parent/.$base.task0."* ]] || die 'staging path escaped destination parent'
    destination_lock="$parent/.$base.task0.lock"
    published=0
    immutable_paths=()
    trap cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM
    command mkdir -p "$stage_root/images" "$stage_root/manifests" "$stage_root/evidence"

    if [[ "$selected_profile" == 'all' ]]; then
        for profile in "${PROFILES[@]}"; do
            if [[ "$profile" == 'fusion' ]]; then
                generate_fusion_profile
            else
                generate_sparse_profile "$profile"
            fi
        done
    elif [[ "$selected_profile" == 'fusion' ]]; then
        generate_fusion_profile
    else
        generate_sparse_profile "$selected_profile"
    fi

    python3 - "$stage_root" "$selected_profile" <<'PY'
import json
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
profiles = sorted(path.stem for path in (root / "manifests").glob("*.json"))
(root / ".complete").write_text(json.dumps({"schemaVersion": 1, "selection": sys.argv[2], "profiles": profiles}, sort_keys=True) + "\n", encoding="ascii")
PY
    readonly_file "$stage_root/.complete"
    command mkdir "$destination_lock" || die 'another publication owns this destination'
    if [[ "$test_publish_race" -eq 1 ]]; then
        command mkdir "$destination_abs"
        printf 'preexisting-destination\n' >"$destination_abs/sentinel.txt"
    fi
    atomic_move_no_replace "$stage_root" "$destination_abs" || die 'destination appeared before atomic publication'
    published=1
    command rmdir "$destination_lock"
    destination_lock=''
    stage_root=''
    trap - EXIT INT TERM
}

parse_arguments() {
    destination=''
    selected_profile='all'
    credential_reference=''
    fusion_store_a=''
    fusion_store_b=''
    while [[ "$#" -gt 0 ]]; do
        case "$1" in
            --destination|--profile|--credential-reference|--fusion-store-a|--fusion-store-b)
                [[ "$#" -ge 2 && -n "$2" ]] || die "missing value for $1"
                case "$1" in
                    --destination) destination="$2" ;;
                    --profile) selected_profile="$2" ;;
                    --credential-reference) credential_reference="$2" ;;
                    --fusion-store-a) fusion_store_a="$2" ;;
                    --fusion-store-b) fusion_store_b="$2" ;;
                esac
                shift 2
                ;;
            --help) usage; exit 0 ;;
            *) die "unknown argument: $1" ;;
        esac
    done
}

platform_name() {
    if [[ -n "$test_platform_name" ]]; then
        printf '%s\n' "$test_platform_name"
    else
        command uname -s
    fi
}

prepare_generation() {
    [[ "$(platform_name)" == 'Darwin' ]] || die 'generation requires Darwin'
    [[ -n "$destination" ]] || die '--destination is required for generation'
    is_known_profile "$selected_profile" || [[ "$selected_profile" == 'all' ]] || die "unknown profile: $selected_profile"
    die 'owned APFS observer is unavailable until Task 1'
    destination_abs="$(canonical_new_path "$destination")"
    assert_outside_repository "$destination_abs"
    if [[ "$test_mode" -eq 0 ]]; then
        command -v hdiutil >/dev/null || die 'required command unavailable: hdiutil'
        command -v diskutil >/dev/null || die 'required command unavailable: diskutil'
        command -v plutil >/dev/null || die 'required command unavailable: plutil'
    fi
    if [[ "$selected_profile" == 'all' || "$selected_profile" == 'password-encryption' ]]; then
        [[ "$credential_reference" =~ ^keychain:[A-Za-z0-9][A-Za-z0-9._/-]*$ ]] || die 'password encryption requires a keychain: reference'
    fi
    if [[ "$selected_profile" == 'all' || "$selected_profile" == 'fusion' ]]; then
        [[ -n "$fusion_store_a" && -n "$fusion_store_b" ]] || die 'Fusion generation requires two distinct store inputs'
        fusion_store_a="$(canonical_existing_file "$fusion_store_a")"
        fusion_store_b="$(canonical_existing_file "$fusion_store_b")"
        [[ "$fusion_store_a" != "$fusion_store_b" ]] || die 'Fusion generation requires two distinct store inputs'
        assert_outside_repository "$fusion_store_a"
        assert_outside_repository "$fusion_store_b"
        require_distinct_files "$fusion_store_a" "$fusion_store_b" || die 'Fusion store inputs are the same file'
    fi
}

run_self_test() {
    test_mode=1
    test_self_root="$(mktemp -d "${TMPDIR:-/tmp}/apfs-compat-self-test.XXXXXXXX")"
    test_command_log="$test_self_root/commands.log"
    : >"$test_command_log"
    selected_profile='all'
    credential_reference='keychain:apfs-access-self-test'
    destination="$test_self_root/corpus"
    destination_abs="$destination"
    fusion_store_a="$test_self_root/fusion-a.img"
    fusion_store_b="$test_self_root/fusion-b.img"
    command dd if=/dev/zero of="$fusion_store_a" bs=4096 count=2 >/dev/null 2>&1
    command dd if=/dev/zero of="$fusion_store_b" bs=4096 count=2 >/dev/null 2>&1
    printf '\001' | command dd of="$fusion_store_b" bs=1 seek=0 conv=notrunc >/dev/null 2>&1
    readonly_file "$fusion_store_a"
    readonly_file "$fusion_store_b"
    run_generation

    local count
    count="$(command find "$destination/manifests" -name '*.json' -type f | command wc -l | command tr -d ' ')"
    [[ "$count" == "${#PROFILES[@]}" && -f "$destination/.complete" ]] || die 'self-test did not publish all profiles'
    command grep -F $'diskutil\tapfs\taddVolume' "$test_command_log" | command grep -F $'\t-groupWith\t/dev/disk99s2' >/dev/null || die 'volume-group command did not use -groupWith'
    ! command grep -F -e '-groupWithVolume' "$test_command_log" >/dev/null || die 'obsolete volume-group option was used'
    ! command grep -E $'^(cp|mv|rm)\t--(\t|$)' "$test_command_log" >/dev/null || die 'GNU-style standalone -- reached a BSD file command'
    command grep -E $'^(cp|mv|rm)\t' "$test_command_log" >/dev/null || die 'file-operation vectors were not exercised'
    python3 - "$destination/images/corruption-source.sparseimage" <<'PY'
import os
import stat
import sys
if os.stat(sys.argv[1]).st_mode & (stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH):
    raise SystemExit(1)
PY
    command grep -F $'chflags\tuchg\t' "$test_command_log" >/dev/null || die 'corruption source immutable command was not exercised'
    validate_manifest "$destination/manifests/fusion.json" "$destination" >/dev/null

    local immutable_window_destination="$test_self_root/immutable-window-corpus"
    if ( destination_abs="$immutable_window_destination"; selected_profile='corruption'; test_fail_immutable_window=1; run_generation ) >/dev/null 2>&1; then
        die 'immutable registration-window failure unexpectedly succeeded'
    fi
    [[ ! -e "$immutable_window_destination" ]] || die 'immutable registration-window failure published a destination'
    assert_no_staging_leftovers "$test_self_root" 'immutable-window-corpus' 'immutable registration-window failure left staging output'
    command grep -F $'chflags\tnouchg\t' "$test_command_log" >/dev/null || die 'immutable registration-window cleanup did not clear its owned file'

    local race_destination="$test_self_root/publication-race-corpus"
    if ( destination_abs="$race_destination"; selected_profile='single-volume'; test_publish_race=1; run_generation ) >/dev/null 2>&1; then
        die 'atomic no-replace publication race unexpectedly succeeded'
    fi
    [[ -f "$race_destination/sentinel.txt" ]] || die 'atomic no-replace publication overwrote the competing destination'
    [[ "$(command cat "$race_destination/sentinel.txt")" == 'preexisting-destination' ]] || die 'competing destination content changed'
    assert_no_staging_leftovers "$test_self_root" 'publication-race-corpus' 'publication race left staging output'

    local dangling_source="$test_self_root/dangling-source"
    local dangling_destination="$test_self_root/dangling-destination"
    command mkdir "$dangling_source"
    printf 'source-survives\n' >"$dangling_source/sentinel.txt"
    python3 - "$test_self_root/missing-destination-target" "$dangling_destination" <<'PY'
import os
import sys
os.symlink(sys.argv[1], sys.argv[2])
PY
    if atomic_move_no_replace "$dangling_source" "$dangling_destination" >/dev/null 2>&1; then
        die 'atomic no-replace publication replaced a dangling destination'
    fi
    [[ -f "$dangling_source/sentinel.txt" ]] && { [[ -e "$dangling_destination" ]] || [[ -L "$dangling_destination" ]]; } || die 'dangling-destination refusal changed either path'

    local output_link_root="$test_self_root/output-link-probes"
    command mkdir -p "$output_link_root/evidence" "$output_link_root/manifests" "$output_link_root/external"
    printf '{}\n' >"$output_link_root/external/evidence.json"
    printf '{}\n' >"$output_link_root/external/manifest.json"
    python3 - "$output_link_root" <<'PY'
import os
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
os.symlink(root / "external/evidence.json", root / "evidence/profile-observer.json")
os.symlink(root / "external/manifest.json", root / "manifests/profile.draft.json")
PY
    if require_regular_file_nofollow "$output_link_root/evidence/profile-observer.json" "$output_link_root/evidence" >/dev/null 2>&1; then
        die 'symlinked observer evidence unexpectedly passed no-follow validation'
    fi
    if require_regular_file_nofollow "$output_link_root/manifests/profile.draft.json" "$output_link_root/manifests" >/dev/null 2>&1; then
        die 'symlinked draft manifest unexpectedly passed no-follow validation'
    fi

    local production_gate_error="$test_self_root/production-gate.err"
    if ( test_platform_name='Darwin'; destination="$test_self_root/production-corpus"; selected_profile='single-volume'; prepare_generation ) 2>"$production_gate_error"; then
        die 'production generation proceeded without the Task 1 observer'
    fi
    command grep -F 'owned APFS observer is unavailable until Task 1' "$production_gate_error" >/dev/null || die 'production observer gate did not fail closed'
    [[ ! -e "$test_self_root/production-corpus" ]] || die 'production observer gate created output'

    local security_calls encrypted_create_calls encrypted_attach_calls
    security_calls="$(command grep -c $'^security\tfind-generic-password\t-w\t-s\tapfs-access-self-test$' "$test_command_log" || true)"
    encrypted_create_calls="$(command grep -Ec $'^hdiutil\tcreate\t.*\t-encryption\tAES-256\t-stdinpass\t.*/password-encryption\.sparseimage$' "$test_command_log" || true)"
    encrypted_attach_calls="$(command grep -Ec $'^hdiutil\tattach\t-stdinpass\t-nobrowse\t-plist\t.*/password-encryption\.sparseimage$' "$test_command_log" || true)"
    [[ "$encrypted_create_calls" -ge 1 && "$encrypted_attach_calls" -eq "$encrypted_create_calls" && "$security_calls" -eq $((encrypted_create_calls + encrypted_attach_calls)) ]] || die 'password fixture did not perform one bounded lookup per encrypted create and attach'
    command grep -E $'^hdiutil\tcreate\t.*\t-encryption\tAES-256\t-stdinpass\t.*/password-encryption\.sparseimage$' "$test_command_log" >/dev/null || die 'encrypted create did not consume stdin password'
    command grep -E $'^hdiutil\tattach\t-stdinpass\t-nobrowse\t-plist\t.*/password-encryption\.sparseimage$' "$test_command_log" >/dev/null || die 'encrypted attach did not consume stdin password'
    ! command grep -F 'self-test-password' "$test_command_log" >/dev/null || die 'credential value leaked into the command log'

    python3 - "$destination/manifests/single-volume.json" "$destination/manifests/fusion.json" <<'PY'
import json
import pathlib
import sys

single = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
fusion = json.loads(pathlib.Path(sys.argv[2]).read_text(encoding="utf-8"))
observation = single["observation"]
single_artifacts = {item["id"]: item for item in single["artifacts"]}
fusion_artifacts = {item["id"]: item for item in fusion["artifacts"]}
if observation["recordSha256"] != single_artifacts[observation["evidenceArtifactId"]]["sha256"]:
    raise SystemExit("synthetic observation is not bound to its evidence artifact")
if len({fusion_artifacts[artifact_id]["path"] for artifact_id in fusion["fusion"]["artifactIds"]}) != 2:
    raise SystemExit("Fusion recipe did not preserve two unique artifact paths")
PY

    local authority_manifest="$test_self_root/authority-probe.json"
    copy_file "$destination/manifests/single-volume.json" "$authority_manifest"
    command chmod u+w "$authority_manifest"
    python3 - "$authority_manifest" <<'PY'
import hashlib
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["artifacts"].append({
    "id": "artifact:observer-2",
    "path": "evidence/second-observer.json",
    "kind": "observer-output",
    "storage": "destination",
    "sha256": "d" * 64,
    "sizeBytes": 512,
    "readOnly": True,
    "storeId": None,
})
data["topology"]["volumes"][0]["evidenceArtifactId"] = "artifact:observer-2"
payload = "".join(f"{item['id']}:{item['sha256']}\n" for item in sorted(data["artifacts"], key=lambda item: item["id"]))
data["sha256"] = hashlib.sha256(payload.encode("ascii")).hexdigest()
path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$authority_manifest" >/dev/null 2>&1; then
        die 'manifest bound to a second observer artifact unexpectedly succeeded'
    fi
    remove_file "$authority_manifest"

    local clone_authority_manifest="$test_self_root/clone-authority-probe.json"
    copy_file "$destination/manifests/clones.json" "$clone_authority_manifest"
    command chmod u+w "$clone_authority_manifest"
    python3 - "$clone_authority_manifest" <<'PY'
import hashlib
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["artifacts"].append({
    "id": "artifact:observer-2",
    "path": "evidence/second-observer.json",
    "kind": "observer-output",
    "storage": "destination",
    "sha256": "d" * 64,
    "sizeBytes": 512,
    "readOnly": True,
    "storeId": None,
})
data["content"]["clones"][0]["evidenceArtifactId"] = "artifact:observer-2"
payload = "".join(f"{item['id']}:{item['sha256']}\n" for item in sorted(data["artifacts"], key=lambda item: item["id"]))
data["sha256"] = hashlib.sha256(payload.encode("ascii")).hexdigest()
path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$clone_authority_manifest" >/dev/null 2>&1; then
        die 'clone bound to a second observer artifact unexpectedly succeeded'
    fi
    remove_file "$clone_authority_manifest"

    local envelope_root="$test_self_root/envelope-probe"
    local envelope_manifest="$test_self_root/envelope-probe.json"
    python3 - "$destination" "$envelope_root" "$envelope_manifest" <<'PY'
import hashlib
import json
import pathlib
import shutil
import sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
manifest_path = pathlib.Path(sys.argv[3])
data = json.loads((source / "manifests/single-volume.json").read_text(encoding="utf-8"))
for artifact in data["artifacts"]:
    target_file = target / artifact["path"]
    target_file.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(source / artifact["path"], target_file)
    target_file.chmod(0o644)
    if artifact["id"] == data["observation"]["evidenceArtifactId"]:
        record = json.loads(target_file.read_text(encoding="utf-8"))
        record["observerVersion"] = "9.9.9"
        target_file.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    digest = hashlib.sha256()
    with target_file.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    artifact["sha256"] = digest.hexdigest()
    artifact["sizeBytes"] = target_file.stat().st_size
    target_file.chmod(0o444)
payload = "".join(f"{item['id']}:{item['sha256']}\n" for item in sorted(data["artifacts"], key=lambda item: item["id"]))
data["sha256"] = hashlib.sha256(payload.encode("ascii")).hexdigest()
manifest_path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$envelope_manifest" "$envelope_root" >/dev/null 2>&1; then
        die 'manifest with a mismatched evidence envelope unexpectedly succeeded'
    fi

    local fusion_unrelated="$test_self_root/fusion-unrelated-probe.json"
    copy_file "$destination/manifests/fusion.json" "$fusion_unrelated"
    command chmod u+w "$fusion_unrelated"
    python3 - "$fusion_unrelated" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
diskutils = [item["id"] for item in data["artifacts"] if item["kind"] == "diskutil-output"]
if len(diskutils) < 2:
    raise SystemExit("fusion probe requires two diskutil artifacts")
data["fusion"]["artifactIds"] = diskutils[:2]
path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$fusion_unrelated" >/dev/null 2>&1; then
        die 'fusion manifest with unrelated artifacts unexpectedly succeeded'
    fi
    remove_file "$fusion_unrelated"

    local fusion_swapped="$test_self_root/fusion-swapped-probe.json"
    copy_file "$destination/manifests/fusion.json" "$fusion_swapped"
    command chmod u+w "$fusion_swapped"
    python3 - "$fusion_swapped" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["topology"]["stores"][0]["artifactId"] = "artifact:store-b"
path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$fusion_swapped" >/dev/null 2>&1; then
        die 'fusion manifest with swapped store binding unexpectedly succeeded'
    fi
    remove_file "$fusion_swapped"

    local alias_input="$test_self_root/fusion-alias.img"
    command ln "$fusion_store_a" "$alias_input"
    if require_distinct_files "$fusion_store_a" "$alias_input" >/dev/null 2>&1; then
        die 'same-file fusion inputs unexpectedly passed distinct-file validation'
    fi
    remove_file "$alias_input"

    local portable_probe_root="$test_self_root/portable-depth-probe"
    command mkdir -p "$portable_probe_root/.portable-depth.task0.probe"
    if ( assert_no_staging_leftovers "$portable_probe_root" 'portable-depth' 'probe sentinel' ) >/dev/null 2>&1; then
        die 'portable depth-one check missed staged output'
    fi
    command rmdir "$portable_probe_root/.portable-depth.task0.probe"
    assert_no_staging_leftovers "$portable_probe_root" 'portable-depth' 'portable depth-one check reported staged output after cleanup'
    command rmdir "$portable_probe_root"

    local parent_link_root="$test_self_root/output-parent-probes"
    command mkdir -p "$parent_link_root/real-evidence" "$parent_link_root/manifests"
    printf 'evidence\n' >"$parent_link_root/real-evidence/profile-observer.json"
    python3 - "$parent_link_root" <<'PY'
import os
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
os.symlink(root / "real-evidence", root / "evidence")
PY
    if require_regular_file_nofollow "$parent_link_root/evidence/profile-observer.json" "$parent_link_root/evidence" >/dev/null 2>&1; then
        die 'symlinked output parent unexpectedly passed no-follow validation'
    fi

    local missing_manifest="$test_self_root/missing-observation.json"
    copy_file "$destination/manifests/single-volume.json" "$missing_manifest"
    command chmod u+w "$missing_manifest"
    python3 - "$missing_manifest" <<'PY'
import json
import pathlib
import sys
path = pathlib.Path(sys.argv[1])
data = json.loads(path.read_text(encoding="utf-8"))
data["topology"]["volumes"][0].pop("incompatibleFeatureBits")
path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$missing_manifest" >/dev/null 2>&1; then
        die 'manifest missing raw APFS observations unexpectedly succeeded'
    fi
    remove_file "$missing_manifest"

    local symlink_root="$test_self_root/symlink-corpus"
    local symlink_manifest="$test_self_root/symlink-manifest.json"
    python3 - "$destination" "$symlink_root" "$symlink_manifest" <<'PY'
import json
import os
import pathlib
import shutil
import sys
source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
manifest_path = pathlib.Path(sys.argv[3])
data = json.loads((source / "manifests/single-volume.json").read_text(encoding="utf-8"))
for artifact in data["artifacts"]:
    source_file = source / artifact["path"]
    target_file = target / artifact["path"]
    target_file.parent.mkdir(parents=True, exist_ok=True)
    if artifact["id"] == "artifact:image":
        os.symlink(source_file, target_file)
    else:
        shutil.copy2(source_file, target_file)
manifest_path.write_text(json.dumps(data, sort_keys=True, indent=2) + "\n", encoding="utf-8")
PY
    if validate_manifest "$symlink_manifest" "$symlink_root" >/dev/null 2>&1; then
        die 'symlink-bearing artifact path unexpectedly succeeded'
    fi

    printf 'SELF-TEST PASS: 18 generated profiles\n'
    printf 'SELF-TEST PASS: authoritative observations enforced\n'
    printf 'SELF-TEST PASS: volume group uses -groupWith\n'
    printf 'SELF-TEST PASS: staged cleanup\n'
    printf 'SELF-TEST PASS: corruption source read-only\n'
    printf 'SELF-TEST PASS: fusion identities observed\n'
    printf 'SELF-TEST PASS: BSD file command vectors\n'
    printf 'SELF-TEST PASS: symlink path containment\n'
    printf 'SELF-TEST PASS: C0a observer publication fail-closed\n'
    printf 'SELF-TEST PASS: contract-only synthetic observations\n'
    printf 'SELF-TEST PASS: single observation authority\n'
    printf 'SELF-TEST PASS: fusion sealed store binding\n'
    printf 'SELF-TEST PASS: portable depth-one checks\n'
    printf 'SELF-TEST PASS: symlinked output parents refused\n'
    printf 'SELF-TEST PASS: Fusion recipe pair uniqueness\n'
    printf 'SELF-TEST PASS: immutable registration-window cleanup\n'
    printf 'SELF-TEST PASS: atomic no-replace destination race\n'
    printf 'SELF-TEST PASS: no-follow declared outputs\n'
    printf 'SELF-TEST PASS: encrypted create and attach vectors\n'
    printf 'SELF-TEST PASS: streamed artifact hashing\n'
    stage_root=''
    command chmod -R u+w "$test_self_root"
    command rm -rf "$test_self_root"
}

main() {
    if [[ "${1:-}" == '--validate-manifest' ]]; then
        [[ "$#" -eq 2 ]] || die '--validate-manifest requires exactly one file or -'
        validate_manifest "$2"
        return
    fi
    if [[ "${1:-}" == '--self-test' ]]; then
        [[ "$#" -eq 1 ]] || die '--self-test accepts no other arguments'
        run_self_test
        return
    fi
    parse_arguments "$@"
    prepare_generation
    run_generation
}

main "$@"
