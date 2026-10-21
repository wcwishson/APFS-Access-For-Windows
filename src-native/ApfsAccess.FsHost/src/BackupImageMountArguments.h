#pragma once

bool BackupLowerHex(std::wstring_view text, std::size_t size)
{
    return text.size() == size && std::all_of(text.begin(), text.end(), [](auto ch) {
        return (ch >= L'0' && ch <= L'9') || (ch >= L'a' && ch <= L'f');
    });
}

bool ParseBackupImageOption(std::wstring_view name, const std::wstring& value,
    backup_image_mount::Options& options)
{
    if (name == L"--backup-volume-uuid") options.volume_uuid = value;
    else if (name == L"--backup-source-sha256") options.source_sha256 = value;
    else if (name == L"--backup-file-identity") options.file_identity = value;
    else if (name == L"--backup-journal-root") options.journal_root = value;
    else if (name == L"--backup-checkpoint-xid") {
        if (!IsCanonicalNonzeroDecimal(value)) return false;
        try { options.checkpoint_xid = std::stoull(value); } catch (...) { return false; }
    }
    else return false;
    return true;
}

bool ValidateBackupImageArguments(const Arguments& a)
{
    const auto& b = a.backup_image;
    return a.readwrite && !a.readonly && !a.allow_raw_physical_write &&
        a.device_offset_bytes == 0 && !a.device.empty() && !IsRawPhysicalDevicePath(a.device) &&
        a.container_manifest.empty() && !a.enable_image_snapshots && !a.enable_raw_snapshots &&
        !a.enable_retained_physical_snapshot_inventory && !a.encrypted.enabled &&
        !a.fusion.enabled && !a.system_data.enabled && !a.snapshot_xid && a.snapshot_name.empty() &&
        a.volume_object_id && IsValidContainerId(a.container_id) &&
        !a.recovery_identity.empty() && !a.management_journal_directory.empty() &&
        !a.status_file.empty() && IsWriteBackendMode(a.write_backend, L"Native") &&
        IsRecoveryPolicyFailClosed(a.write_recovery_policy) &&
        a.write_require_canonical_commit && a.write_integrity_check_on_mount &&
        !a.allow_legacy_scaffold_for_fixtures && a.write_max_dirty_transactions == 1 &&
        b.checkpoint_xid && BackupLowerHex(b.volume_uuid, 32) &&
        BackupLowerHex(b.source_sha256, 64) && BackupLowerHex(b.file_identity, 80) &&
        !b.journal_root.empty() && std::filesystem::path(b.journal_root).is_absolute();
}
